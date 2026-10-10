"""Tool registry: CRUD + seeding from YAML specs."""
from __future__ import annotations

import json
import os

import yaml

from .db import connect

SEED_DIR = os.environ.get("CPTM_SEED_DIR", "/seeds")
TOOLBOX_IMAGE = os.environ.get("CPTM_TOOLBOX_IMAGE", "cptm-toolbox:latest")


async def seed_tools() -> None:
    """Load seed specs from /seeds into the registry.

    Built-in tools are refreshed whenever their YAML changes, so fixing a seed
    spec actually takes effect on restart. Custom tools added via the GUI are
    never touched, and a built-in the user has edited (modified=1) is left alone.
    """
    if not os.path.isdir(SEED_DIR):
        return
    conn = await connect()
    try:
        for fname in sorted(os.listdir(SEED_DIR)):
            if not fname.endswith(".yaml"):
                continue
            path = os.path.join(SEED_DIR, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    spec = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                # One bad spec must not stop the API from starting.
                print(f"[seed] skipping malformed spec {fname}: {e}")
                continue
            name = spec.get("name")
            if not name or not spec.get("command_template"):
                print(f"[seed] skipping incomplete spec {fname}")
                continue

            cur = await conn.execute(
                "SELECT built_in, modified FROM tools WHERE name = ?", (name,)
            )
            row = await cur.fetchone()

            values = (
                spec.get("display_name", name),
                spec.get("description", ""),
                spec.get("category", "general"),
                spec.get("docker_image") or TOOLBOX_IMAGE,
                spec["command_template"],
                json.dumps(spec.get("params", [])),
                spec.get("output_type", "raw"),
                json.dumps(spec.get("entrypoint")),
            )

            if row is None:
                await conn.execute(
                    """INSERT INTO tools
                       (name, display_name, description, category, docker_image,
                        command_template, params_json, output_type, entrypoint_json,
                        built_in, modified)
                       VALUES (?,?,?,?,?,?,?,?,?,1,0)""",
                    (name, *values),
                )
                print(f"[seed] added {name}")
            elif row["built_in"] and not row["modified"]:
                # Refresh from disk so seed fixes propagate on restart.
                await conn.execute(
                    """UPDATE tools SET
                         display_name = ?, description = ?, category = ?, docker_image = ?,
                         command_template = ?, params_json = ?, output_type = ?,
                         entrypoint_json = ?
                       WHERE name = ?""",
                    (*values, name),
                )
        await conn.commit()
    finally:
        await conn.close()


async def list_tools() -> list[dict]:
    conn = await connect()
    try:
        cur = await conn.execute("SELECT * FROM tools ORDER BY category, display_name")
        rows = await cur.fetchall()
        return [_tool_row(r) for r in rows]
    finally:
        await conn.close()


async def get(name: str) -> dict | None:
    conn = await connect()
    try:
        cur = await conn.execute("SELECT * FROM tools WHERE name = ?", (name,))
        row = await cur.fetchone()
        return _tool_row(row) if row else None
    finally:
        await conn.close()


async def create(spec: dict, built_in: bool = False) -> dict:
    conn = await connect()
    try:
        await conn.execute(
            """INSERT INTO tools
               (name, display_name, description, category, docker_image,
                command_template, params_json, output_type, entrypoint_json, built_in)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                spec["name"],
                spec.get("display_name", spec["name"]),
                spec.get("description", ""),
                spec.get("category", "general"),
                spec.get("docker_image") or TOOLBOX_IMAGE,
                spec["command_template"],
                json.dumps(spec.get("params", [])),
                spec.get("output_type", "raw"),
                json.dumps(spec.get("entrypoint")),
                1 if built_in else 0,
            ),
        )
        await conn.commit()
    finally:
        await conn.close()
    return await get(spec["name"])


async def update(name: str, spec: dict) -> dict | None:
    conn = await connect()
    try:
        cur = await conn.execute("SELECT built_in FROM tools WHERE name = ?", (name,))
        row = await cur.fetchone()
        if not row:
            return None
        # Mark edited built-ins so seeding won't overwrite the user's version.
        await conn.execute(
            """UPDATE tools SET
                 display_name = ?, description = ?, category = ?, docker_image = ?,
                 command_template = ?, params_json = ?, output_type = ?, entrypoint_json = ?,
                 modified = 1
               WHERE name = ?""",
            (
                spec.get("display_name", name),
                spec.get("description", ""),
                spec.get("category", "general"),
                spec.get("docker_image") or TOOLBOX_IMAGE,
                spec["command_template"],
                json.dumps(spec.get("params", [])),
                spec.get("output_type", "raw"),
                json.dumps(spec.get("entrypoint")),
                name,
            ),
        )
        await conn.commit()
    finally:
        await conn.close()
    return await get(name)


async def delete(name: str) -> bool:
    conn = await connect()
    try:
        cur = await conn.execute("DELETE FROM tools WHERE name = ?", (name,))
        await conn.commit()
        return cur.rowcount > 0
    finally:
        await conn.close()


def _tool_row(row) -> dict:
    d = dict(row)
    d["params"] = json.loads(d.pop("params_json") or "[]")
    d["entrypoint"] = json.loads(d.pop("entrypoint_json") or "null")
    # An empty image means "use the toolbox image" — normalise so the runner
    # never receives a blank image reference.
    if not d.get("docker_image"):
        d["docker_image"] = TOOLBOX_IMAGE
    return d
