"""WebSocket endpoints: live job output + interactive terminal PTY."""
from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import jobs, runner
from ..auth import TOKEN
from ..db import connect

router = APIRouter()
log = logging.getLogger("cptm.ws")

TERMINAL_STATUSES = {"finished", "failed", "cancelled"}


def _authorized(ws: WebSocket) -> bool:
    """Compare the query-string credential against the configured value."""
    supplied = ws.query_params.get("token", "")
    return supplied == TOKEN


def _raw_socket(sock):
    """Docker wraps exec sockets in a SocketIO object exposing read/write helpers.

    For a bidirectional PTY we need the underlying socket, which offers the plain
    `recv`/`sendall` semantics the terminal loop relies on.
    """
    return getattr(sock, "_sock", sock)


async def _job_snapshot(job_id: int):
    """Return (output_text, status) for a job, or (None, None) if unknown."""
    conn = await connect()
    try:
        cur = await conn.execute(
            "SELECT output_text, status FROM jobs WHERE id = ?", (job_id,)
        )
        row = await cur.fetchone()
        return (row["output_text"], row["status"]) if row else (None, None)
    finally:
        await conn.close()


@router.websocket("/ws/jobs/{job_id}")
async def job_output(ws: WebSocket, job_id: int):
    if not _authorized(ws):
        await ws.close(code=4401)
        return
    await ws.accept()

    # If the job already reached a terminal state there will be no further
    # events, and its in-memory buffer has been discarded — serve the persisted
    # output and close out. Without this the UI waits forever on a fast job.
    db_out, status = await _job_snapshot(job_id)
    if status is None:
        await ws.send_text(json.dumps({"type": "done", "status": "unknown"}))
        await ws.close()
        return

    if status in TERMINAL_STATUSES:
        if db_out:
            await ws.send_text(json.dumps({"type": "stream", "data": db_out}))
        await ws.send_text(json.dumps({"type": "done", "status": status}))
        await ws.close()
        return

    # Live job: replay what we have, then follow new output.
    # Subscribe FIRST, then snapshot the buffer — so output produced between the
    # two steps cannot be lost (it lands in the listener set before we read).
    await jobs.subscribe(job_id, ws)
    buffered = await jobs.get_buffered_output(job_id)
    if buffered:
        await ws.send_text(json.dumps({"type": "stream", "data": buffered}))
    try:
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await jobs.unsubscribe(job_id, ws)


@router.websocket("/ws/terminal")
async def terminal(ws: WebSocket):
    if not _authorized(ws):
        await ws.close(code=4401)
        return
    await ws.accept()

    exec_socket = None
    raw = None
    read_task = None

    try:
        await asyncio.to_thread(runner.ensure_toolbox)
        exec_socket = await runner.exec_toolbox(["/bin/bash", "-i"], tty=True)
        raw = _raw_socket(exec_socket)

        async def pump_out():
            try:
                while True:
                    data = await asyncio.to_thread(raw.recv, 4096)
                    if not data:
                        break
                    if isinstance(data, bytes):
                        await ws.send_bytes(data)
                    else:
                        await ws.send_text(data)
            except (WebSocketDisconnect, RuntimeError, OSError):
                pass

        read_task = asyncio.create_task(pump_out())

        while True:
            msg = await ws.receive_text()
            try:
                payload = json.loads(msg)
            except json.JSONDecodeError:
                continue
            if payload.get("type") == "input":
                data = payload.get("data", "")
                if data:
                    await asyncio.to_thread(raw.sendall, data.encode())
            # interactive tty resize is a no-op in this version
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception:
        log.exception("terminal error")
    finally:
        if read_task:
            read_task.cancel()
        for sock in (raw, exec_socket):
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass
