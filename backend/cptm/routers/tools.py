"""Tools API: list/create/update/delete tool specs."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Literal, Optional

from .. import registry
from ..auth import require_token

router = APIRouter(dependencies=[Depends(require_token)])


class ParamSpec(BaseModel):
    name: str
    label: str = ""
    # "flag" renders as `--flag value`, or vanishes from the command when empty,
    # which is what optional CLI switches need.
    type: Literal["string", "bool", "select", "flag"] = "string"
    flag: str = ""
    default: str = ""
    required: bool = False
    help: str = ""
    options: list[str] = Field(default_factory=list)


class ToolSpec(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    display_name: str = ""
    description: str = ""
    category: Literal["aws", "azure", "gcp", "kubernetes", "general"] = "general"
    docker_image: str = ""
    command_template: str = Field(min_length=1)
    params: list[ParamSpec] = Field(default_factory=list)
    output_type: Literal[
        "raw", "generic", "prowler", "scoutsuite", "trivy", "kube-hunter",
        "kube-bench", "nmap", "cloud-enum", "cloudbrute", "cloudfox",
        "enumerate-iam", "gcp-scanner", "microburst",
    ] = "generic"
    entrypoint: Optional[list[str]] = None


@router.get("/tools")
async def list_tools() -> list[dict]:
    return await registry.list_tools()


@router.get("/tools/{name}")
async def get_tool(name: str) -> dict:
    tool = await registry.get(name)
    if not tool:
        raise HTTPException(404, "tool not found")
    return tool


@router.post("/tools", status_code=201)
async def create_tool(spec: ToolSpec) -> dict:
    if await registry.get(spec.name):
        raise HTTPException(409, "tool with that name already exists")
    return await registry.create(spec.model_dump())


@router.put("/tools/{name}")
async def update_tool(name: str, spec: ToolSpec) -> dict:
    updated = await registry.update(name, spec.model_dump())
    if not updated:
        raise HTTPException(404, "tool not found")
    return updated


@router.delete("/tools/{name}")
async def delete_tool(name: str) -> dict:
    ok = await registry.delete(name)
    if not ok:
        raise HTTPException(404, "tool not found")
    return {"deleted": name}
