"""Jobs API: launch, list, inspect, cancel, artifacts, findings."""
from __future__ import annotations

import json
import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .. import jobs, registry
from ..auth import require_token
from ..db import connect
from ..parsers import parse_output

router = APIRouter(dependencies=[Depends(require_token)])

ARTIFACTS_DIR = os.environ.get("CPTM_ARTIFACTS", "/artifacts")


class LaunchRequest(BaseModel):
    tool: str
    params: dict = {}


# Placeholders the backend injects automatically; never treated as user input.
AUTO_PARAMS = {"job_id"}


@router.post("/jobs/launch")
async def launch(req: LaunchRequest) -> dict:
    tool = await registry.get(req.tool)
    if not tool:
        raise HTTPException(404, f"tool '{req.tool}' not found")
    # Validate required params present (auto-injected ones are exempt).
    for p in tool["params"]:
        if p.get("required") and p["name"] not in AUTO_PARAMS and not req.params.get(p["name"]):
            raise HTTPException(400, f"missing required parameter: {p['name']}")
    # Merge defaults
    params = {p["name"]: p.get("default", "") for p in tool["params"]}
    params.update({k: v for k, v in req.params.items() if v})
    try:
        job_id = await jobs.launch(tool, params)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"job_id": job_id}


@router.get("/jobs")
async def list_jobs(limit: int = 50) -> list[dict]:
    conn = await connect()
    try:
        cur = await conn.execute(
            """SELECT j.id, j.tool_name, j.display_name, j.command, j.status,
                      j.exit_code, j.started_at, j.finished_at, j.error
               FROM jobs j ORDER BY j.id DESC LIMIT ?""",
            (limit,),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        await conn.close()


@router.get("/jobs/{job_id}")
async def get_job(job_id: int) -> dict:
    conn = await connect()
    try:
        cur = await conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "job not found")
        d = dict(row)
        d.pop("output_text", None)  # big; fetch separately
        cur = await conn.execute(
            "SELECT id, path, size, created_at FROM artifacts WHERE job_id = ?",
            (job_id,),
        )
        d["artifacts"] = [dict(r) for r in await cur.fetchall()]
        return d
    finally:
        await conn.close()


@router.get("/jobs/{job_id}/output")
async def get_output(job_id: int) -> dict:
    conn = await connect()
    try:
        cur = await conn.execute(
            "SELECT output_text, status FROM jobs WHERE id = ?", (job_id,)
        )
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "job not found")
    finally:
        await conn.close()
    live = await jobs.get_buffered_output(job_id)
    text = live or row["output_text"]
    return {"status": row["status"], "output": text}


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: int) -> dict:
    ok = await jobs.cancel(job_id)
    return {"cancelled": ok}


@router.get("/jobs/{job_id}/findings")
async def get_findings(job_id: int) -> dict:
    conn = await connect()
    try:
        cur = await conn.execute(
            "SELECT output_text FROM jobs WHERE id = ?", (job_id,)
        )
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "job not found")
        cur = await conn.execute(
            "SELECT t.output_type FROM jobs j JOIN tools t ON t.name = j.tool_name WHERE j.id = ?",
            (job_id,),
        )
        trow = await cur.fetchone()
        cur = await conn.execute(
            "SELECT path FROM artifacts WHERE job_id = ? ORDER BY size DESC", (job_id,)
        )
        artifacts = [dict(r) for r in await cur.fetchall()]
    finally:
        await conn.close()

    output_type = trow["output_type"] if trow else "raw"

    # Parse the console output first — for most raw tools (nmap, cloud-enum,
    # cloudbrute, enumerate-iam, cloudfox) stdout is where the results live.
    console = parse_output(output_type, row["output_text"] or "")
    console["source"] = "stdout"
    best = console

    # Then merge in anything parseable from report artifacts (trivy, prowler,
    # scoutsuite write files; cloudfox writes loot files). Findings already
    # present (by id+resource) are not duplicated.
    seen = {(f.get("id"), f.get("resource")) for f in best.get("findings", [])}
    base_dir = os.path.realpath(ARTIFACTS_DIR)
    for art in artifacts:
        full = os.path.realpath(os.path.join(base_dir, art["path"]))
        if not full.startswith(base_dir + os.sep) or not os.path.isfile(full):
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                text = f.read(5_000_000)
        except OSError:
            continue
        parsed = parse_output(output_type, text)
        fresh = [
            f for f in parsed.get("findings", [])
            if (f.get("id"), f.get("resource")) not in seen
        ]
        if fresh:
            for f in fresh:
                seen.add((f.get("id"), f.get("resource")))
            merged = dict(best)
            merged["findings"] = (best.get("findings", []) + fresh)[:2000]
            merged["summary"] = {
                **merged.get("summary", {}),
                "total_findings": len(merged["findings"]),
            }
            merged.setdefault("sources", []).append(art["path"])
            best = merged

    return best


@router.get("/jobs/{job_id}/artifacts/{path:path}")
async def download_artifact(job_id: int, path: str) -> FileResponse:
    # path is relative to /artifacts (e.g. jobs/12/report.html)
    base = os.path.realpath(ARTIFACTS_DIR)
    full = os.path.realpath(os.path.join(base, path))
    if not full.startswith(base + os.sep) or not os.path.isfile(full):
        raise HTTPException(404, "artifact not found")
    return FileResponse(full)
