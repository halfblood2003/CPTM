"""Docker runner: spawn per-job tool containers and stream their output."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

import docker
from docker.errors import APIError, ImageNotFound, NotFound

from .db import connect

log = logging.getLogger("cptm.runner")

TOOLBOX_IMAGE = os.environ.get("CPTM_TOOLBOX_IMAGE", "cptm-toolbox:latest")
WORKSPACE_DIR = os.environ.get("CPTM_WORKSPACE", "/workspace")
ARTIFACTS_DIR = os.environ.get("CPTM_ARTIFACTS", "/artifacts")
CRED_DIR = os.environ.get("CPTM_CRED_DIR", "/creds")
DOCKER_NETWORK = os.environ.get("CPTM_NETWORK", "cptm-net")
# Job containers inherit the toolbox container's volume/bind mounts, so the
# Docker daemon (not this process) resolves host paths. This is what makes
# credentials, /workspace and /artifacts line up without hard-coding host dirs.
VOLUMES_FROM = os.environ.get("CPTM_VOLUMES_FROM", "cptm-toolbox")

_client: Optional[docker.DockerClient] = None


def get_client() -> docker.DockerClient:
    global _client
    if _client is None:
        _client = docker.from_env()
    return _client


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_mounts() -> list:
    """Legacy helper kept for the terminal/toolbox path.

    Job containers no longer use explicit mounts: they inherit the toolbox
    container's mounts via `volumes_from` so host paths are resolved by the
    daemon rather than guessed here.
    """
    return []


async def pull_image_if_missing(image: str) -> None:
    """Pull images that are not the local toolbox and not present locally."""
    if not image or image == TOOLBOX_IMAGE:
        return

    def _ensure() -> None:
        client = get_client()
        try:
            client.images.get(image)
        except ImageNotFound:
            log.info("pulling image %s", image)
            client.images.pull(image)

    await asyncio.to_thread(_ensure)


async def start_job_container(
    job_id: int,
    image: str,
    command: list[str],
    entrypoint: Optional[list[str]],
) -> str:
    """Create + start the job container. Returns container id."""
    name = f"cptm-job-{job_id}"

    def _create() -> str:
        client = get_client()
        try:
            client.containers.get(name).remove(force=True)
        except NotFound:
            pass
        container = client.containers.run(
            image,
            command=command,
            entrypoint=entrypoint,
            name=name,
            detach=True,
            network=DOCKER_NETWORK,
            volumes_from=[VOLUMES_FROM],
            environment={"CPTM_JOB_ID": str(job_id), "TERM": "xterm-256color"},
            auto_remove=False,  # we inspect exit code + logs before removing
            stdin_open=False,
            tty=False,
        )
        return container.id

    return await asyncio.to_thread(_create)


async def stream_logs(container_id: str) -> AsyncIterator[dict]:
    """Yield {'stream': chunk} log records until the container exits."""
    log.info("stream_logs start for %s", container_id[:12])

    def _open_stream():
        client = get_client()
        container = client.containers.get(container_id)
        return container.logs(stream=True, follow=True, stdout=True, stderr=True)

    stream = await asyncio.to_thread(_open_stream)
    try:
        while True:
            def _next_chunk():
                try:
                    return next(stream)
                except StopIteration:
                    return None
            chunk = await asyncio.to_thread(_next_chunk)
            if chunk is None:
                break
            text = chunk.decode("utf-8", errors="replace")
            yield {"stream": text}
    finally:
        stream.close()


async def wait_container(container_id: str) -> int:
    def _wait() -> int:
        client = get_client()
        container = client.containers.get(container_id)
        result = container.wait()
        return result.get("StatusCode", -1)

    return await asyncio.to_thread(_wait)


async def remove_container(container_id: str) -> None:
    def _rm() -> None:
        client = get_client()
        try:
            client.containers.get(container_id).remove(force=True)
        except (NotFound, APIError):
            pass

    await asyncio.to_thread(_rm)


async def list_artifacts(job_id: int) -> list[dict]:
    """Files a job wrote under /artifacts/jobs/<job_id>."""
    base = os.path.join(ARTIFACTS_DIR, "jobs", str(job_id))

    def _walk() -> list[dict]:
        found = []
        for root, _dirs, files in os.walk(base):
            for f in files:
                p = os.path.join(root, f)
                try:
                    size = os.path.getsize(p)
                except OSError:
                    size = 0
                found.append(
                    {
                        "path": os.path.relpath(p, ARTIFACTS_DIR),
                        "abs_path": p,
                        "size": size,
                    }
                )
        return found

    return await asyncio.to_thread(_walk)


async def record_artifacts(job_id: int) -> None:
    items = await list_artifacts(job_id)
    conn = await connect()
    try:
        await conn.execute("DELETE FROM artifacts WHERE job_id = ?", (job_id,))
        for it in items:
            await conn.execute(
                "INSERT INTO artifacts (job_id, path, size) VALUES (?,?,?)",
                (job_id, it["path"], it["size"]),
            )
        await conn.commit()
    finally:
        await conn.close()


async def exec_toolbox(command: list[str], tty: bool = True):
    """Run an interactive exec in the long-lived toolbox container."""
    def _exec():
        client = get_client()
        container = client.containers.get("cptm-toolbox")
        return container.exec_run(
            command,
            tty=tty,
            stdin=True,
            socket=True,
            demux=False,
        )

    exec_result = await asyncio.to_thread(_exec)
    return exec_result.output  # raw socket


def ensure_toolbox() -> None:
    """Make sure the long-lived toolbox container exists and is running."""
    client = get_client()

    try:
        c = client.containers.get("cptm-toolbox")
        if c.status != "running":
            c.start()
        return
    except NotFound:
        pass
    client.containers.run(
        TOOLBOX_IMAGE,
        name="cptm-toolbox",
        command=["sleep", "infinity"],
        detach=True,
        network=DOCKER_NETWORK,
        environment={"TERM": "xterm-256color"},
        stdin_open=True,
        tty=True,
    )


def write_params_file(job_id: int, params: dict) -> str:
    """Persist job params to the shared workspace so tools can read them."""
    d = os.path.join(WORKSPACE_DIR, "jobs", str(job_id))
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "params.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(params, f, indent=2)
    return path
