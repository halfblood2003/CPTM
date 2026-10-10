"""Per-tool launch inputs for the classification test.

Kept separate from the runner so the harness cannot invent arguments a tool
does not accept (which produces false "bug" reports). Every value here is a
public target, a placeholder, or an empty string - no real credentials.
"""
import os

# Values come from the environment where they are secret-shaped, so no literal
# credential ever appears in source.
PLACEHOLDER = os.environ.get("CPTM_TEST_PLACEHOLDER", "placeholder")

TOOL_INPUTS = {
    "nmap": {"target": "127.0.0.1", "flags": "-sT -Pn -p 8080"},
    "trivy-image": {"scan_type": "image", "target": "alpine:3.19"},
    "prowler-aws": {"profile": "default", "region": "us-east-1"},
    "prowler-azure": {"subscription": "", "auth": "--sp-env-auth"},
    "prowler-gcp": {"project": ""},
    "scoutsuite-aws": {"profile": "default"},
    "scoutsuite-azure": {},
    "scoutsuite-gcp": {"project": "example-project"},
    "cloud-enum": {"keyword": "flaws"},
    "cloudbrute": {"keyword": "flaws", "domain": "flaws.cloud"},
    "cloudfox": {"profile_flag": "-p default", "command": "inventory"},
    "enumerate-iam": {},
    "pmapper": {"profile": "default"},
    "pacu": {
        "profile": "default",
        "exec_flag": "--module-info",
        "module": "iam__enum_users_roles_policies_groups",
    },
    "roadrecon-azure": {
        "username": "pentester@example.com",
        "tenant": "example.onmicrosoft.com",
    },
    "gcp-scanner": {"key_path": "/creds/gcp", "light": ""},
    "kube-hunter": {"target": "127.0.0.1", "mode": ""},
    "kube-bench": {},
    "microburst-azure": {"keyword": "example"},
}


def params_for(tool: dict) -> dict:
    """Fill a tool's params from TOOL_INPUTS, then its own defaults."""
    provided = TOOL_INPUTS.get(tool["name"], {})
    out = {}
    for p in tool.get("params", []):
        name = p["name"]
        if name in provided:
            out[name] = provided[name]
        elif p.get("default"):
            out[name] = p["default"]
        elif p.get("required"):
            lowered = name.lower()
            if any(h in lowered for h in ("pass", "secret")):
                out[name] = PLACEHOLDER
            else:
                out[name] = PLACEHOLDER
        else:
            out[name] = ""
    return out
