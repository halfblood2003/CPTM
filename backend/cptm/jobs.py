"""Job orchestration: run a tool container, stream logs, parse findings."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
from typing import Optional

from . import runner
from .db import connect
from .parsers import parse_output

log = logging.getLogger("cptm.jobs")

ARTIFACTS_DIR = os.environ.get("CPTM_ARTIFACTS", "/artifacts")

# Live listeners per job: websockets waiting for output
_listeners: dict[int, set] = {}
# Buffered output per running job (bounded)
_buffers: dict[int, list] = {}
_tasks: dict[int, asyncio.Task] = {}


async def subscribe(job_id: int, ws):
    _listeners.setdefault(job_id, set()).add(ws)


async def unsubscribe(job_id: int, ws):
    s = _listeners.get(job_id)
    if s and ws in s:
        s.remove(ws)


async def _broadcast(job_id: int, message: dict) -> None:
    payload = json.dumps(message)
    for ws in list(_listeners.get(job_id, ())):
        try:
            await ws.send_text(payload)
        except Exception:
            _listeners.get(job_id, set()).discard(ws)


def _append_buffer(job_id: int, text: str, cap: int = 4000) -> None:
    buf = _buffers.setdefault(job_id, [])
    buf.append(text)
    if len(buf) > cap:
        del buf[: len(buf) - cap]


def render_command(template: str, params: dict) -> str:
    """Substitute {param} placeholders. Unknown params error early."""

    class SafeDict(dict):
        def __missing__(self, key):
            raise KeyError(key)

    try:
        return template.format_map(SafeDict(params))
    except KeyError as e:
        raise ValueError(f"missing required parameter: {e.args[0]}")


def _substitute(template: str, params: dict, job_id: int, param_specs=None) -> str:
    """Render the command template.

    `{job_id}` is injected automatically. Params declared with type "flag" are
    rendered as `--flag value`, or omitted entirely when empty — so optional CLI
    switches work without the user having to hand-write flags into extra_args.
    """
    specs = {p["name"]: p for p in (param_specs or [])}
    merged = dict(params)
    merged["job_id"] = job_id

    for name, spec in specs.items():
        if spec.get("type") != "flag":
            continue
        value = str(params.get(name, "") or "").strip()
        flag = spec.get("flag") or ""
        if value:
            merged[name] = f"{flag} {value}".strip()
        else:
            merged[name] = ""  # flag disappears from the command entirely

    return render_command(template, merged)


def build_command_args(command_str: str) -> list[str]:
    """Turn a rendered command string into container args.

    Commands using shell operators (&&, ||, |, redirects) must run through a
    shell — otherwise the operators are passed to the tool as literal arguments
    and it fails with "unrecognized arguments".
    """
    shell_ops = ("&&", "||", " | ", ">", "<", ";")
    if any(op in command_str for op in shell_ops):
        return ["/bin/sh", "-c", command_str]
    return shlex.split(command_str)


async def get_tool(name: str) -> Optional[dict]:
    conn = await connect()
    try:
        cur = await conn.execute("SELECT * FROM tools WHERE name = ?", (name,))
        row = await cur.fetchone()
        return dict(row) if row else None
    finally:
        await conn.close()


async def create_job(tool: dict, params: dict) -> int:
    # Validate the template against the supplied params before writing a row,
    # so a bad launch never leaves a junk job behind.
    param_specs = tool.get("params") or []
    _substitute(tool["command_template"], params, 0, param_specs)

    conn = await connect()
    try:
        cur = await conn.execute(
            """INSERT INTO jobs (tool_name, display_name, command, status, params_json)
               VALUES (?,?,?,?,?)""",
            (
                tool["name"],
                tool["display_name"],
                tool["command_template"],  # replaced below once we have an id
                "queued",
                json.dumps(params),
            ),
        )
        job_id = cur.lastrowid
        command_str = _substitute(tool["command_template"], params, job_id, param_specs)
        await conn.execute(
            "UPDATE jobs SET command = ? WHERE id = ?", (command_str, job_id)
        )
        await conn.commit()
    finally:
        await conn.close()

    # Make the per-job artifact dir so tools can write straight into it.
    os.makedirs(os.path.join(ARTIFACTS_DIR, "jobs", str(job_id)), exist_ok=True)
    os.makedirs(os.path.join(runner.WORKSPACE_DIR, "jobs", str(job_id)), exist_ok=True)
    return job_id


async def _run_job(job_id: int, tool: dict, params: dict) -> None:
    try:
        await runner.pull_image_if_missing(tool["docker_image"])
        command = build_command_args(
            _substitute(tool["command_template"], params, job_id, tool.get("params") or [])
        )
        entrypoint = tool.get("entrypoint")
        await _set_status(job_id, "running")
        container_id = await runner.start_job_container(
            job_id, tool["docker_image"], command, entrypoint
        )
        conn = await connect()
        try:
            await conn.execute(
                "UPDATE jobs SET container_id = ? WHERE id = ?",
                (container_id, job_id),
            )
            await conn.commit()
        finally:
            await conn.close()

        async def _pump():
            async for chunk in runner.stream_logs(container_id):
                text = chunk.get("stream", "")
                _append_buffer(job_id, text)
                await _broadcast(job_id, {"type": "stream", "data": text})

        pump_task = asyncio.create_task(_pump())
        exit_code = await runner.wait_container(container_id)
        pump_task.cancel()
        try:
            await pump_task
        except (asyncio.CancelledError, Exception):
            pass

        output = "".join(_buffers.get(job_id, []))
        findings = parse_output(tool.get("output_type", "raw"), output)

        conn = await connect()
        try:
            await conn.execute(
                """UPDATE jobs
                   SET status = ?, exit_code = ?, finished_at = datetime('now'),
                       output_text = ?, error = ?
                   WHERE id = ?""",
                (
                    "finished" if exit_code == 0 else "failed",
                    exit_code,
                    output,
                    "" if exit_code == 0 else f"exit code {exit_code}",
                    job_id,
                ),
            )
            await conn.commit()
        finally:
            await conn.close()

        await runner.record_artifacts(job_id)
        await _broadcast(
            job_id,
            {
                "type": "done",
                "status": "finished" if exit_code == 0 else "failed",
                "exit_code": exit_code,
                "findings": findings,
            },
        )
        await runner.remove_container(container_id)
    except Exception as e:
        log.exception("job %s failed", job_id)
        await _set_status(job_id, "failed", error=str(e))
        await _broadcast(job_id, {"type": "done", "status": "failed", "exit_code": -1})
    finally:
        _buffers.pop(job_id, None)
        _tasks.pop(job_id, None)


async def _set_status(job_id: int, status: str, error: str = "") -> None:
    conn = await connect()
    try:
        await conn.execute(
            "UPDATE jobs SET status = ?, error = ? WHERE id = ?", (status, error, job_id)
        )
        await conn.commit()
    finally:
        await conn.close()


async def launch(tool: dict, params: dict) -> int:
    job_id = await create_job(tool, params)
    _tasks[job_id] = asyncio.create_task(_run_job(job_id, tool, params))
    return job_id


async def cancel(job_id: int) -> bool:
    task = _tasks.get(job_id)
    conn = await connect()
    try:
        cur = await conn.execute(
            "SELECT container_id FROM jobs WHERE id = ?", (job_id,)
        )
        row = await cur.fetchone()
    finally:
        await conn.close()
    if row and row["container_id"]:
        await runner.remove_container(row["container_id"])
    if task:
        task.cancel()
        _tasks.pop(job_id, None)
        await _set_status(job_id, "cancelled")
        await _broadcast(job_id, {"type": "done", "status": "cancelled"})
        return True
    await _set_status(job_id, "cancelled")
    await _broadcast(job_id, {"type": "done", "status": "cancelled"})
    return True


async def get_buffered_output(job_id: int) -> str:
    return "".join(_buffers.get(job_id, []))
