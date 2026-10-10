"""Smoke test: exercise API + registry + parsers without Docker."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cptm.db import init_db
from cptm import registry


async def main():
    await init_db()
    await registry.seed_tools()
    tools = await registry.list_tools()
    print("SEEDED_TOOLS", len(tools))


asyncio.run(main())

from fastapi.testclient import TestClient

from cptm.main import app
from cptm.jobs import render_command
from cptm.parsers import parse_output

c = TestClient(app)
H = {"X-CPTM-Token": "change-me"}

r = c.get("/api/health", headers=H)
print("HEALTH", r.status_code, r.json())

r = c.get("/api/tools", headers=H)
print("TOOLS_LIST", r.status_code, len(r.json()))

r = c.get("/api/tools", headers={"X-CPTM-Token": "wrong"})
print("AUTH_REJECT", r.status_code)

r = c.post(
    "/api/tools",
    headers=H,
    json={
        "name": "my-custom-tool",
        "display_name": "My Custom Tool",
        "command_template": "echo {msg}",
        "category": "general",
        "params": [
            {"name": "msg", "label": "Message", "type": "string", "required": True}
        ],
    },
)
print("CREATE_TOOL", r.status_code, r.json().get("name"))

r = c.put(
    "/api/tools/my-custom-tool",
    headers=H,
    json={
        "name": "my-custom-tool",
        "display_name": "My Custom Tool v2",
        "command_template": "echo {msg} v2",
        "params": [],
    },
)
print("UPDATE_TOOL", r.status_code, r.json().get("display_name"))

print(
    "RENDER",
    render_command(
        "prowler aws --profile {profile} {extra_args}",
        {"profile": "engagement1", "extra_args": ""},
    ),
)

r = c.delete("/api/tools/my-custom-tool", headers=H)
print("DELETE_TOOL", r.status_code)

prowler_line = json.dumps(
    {
        "CheckID": "iam-1",
        "Severity": "high",
        "Status": "FAIL",
        "ServiceName": "iam",
        "CheckTitle": "Root MFA not enabled",
        "ResourceDetails": "arn:aws:iam::123:root",
    }
)
out = parse_output("prowler", prowler_line)
print("PARSER_PROWLER", out["summary"])

out2 = parse_output(
    "kube-bench", "[FAIL] 1.2.1 Ensure that the --anonymous-auth argument is set to false"
)
print("PARSER_KUBEBENCH", out2["summary"])

out3 = parse_output(
    "trivy",
    json.dumps(
        {
            "Results": [
                {
                    "Target": "alpine:3.18",
                    "Type": "image",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "Severity": "HIGH",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.1.0",
                        }
                    ],
                }
            ]
        }
    ),
)
print("PARSER_TRIVY", out3["summary"])

print("SMOKE_OK")
