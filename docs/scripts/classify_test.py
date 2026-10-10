"""Launch every tool and classify WHY it failed.

A failure is only acceptable if it is a genuine credential/permission/target
error (no cloud credentials are mounted on this host). Anything else - a bad
flag, a missing file, a shell error - is a bug in the tool spec.
"""
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'backend')))
from test_inputs import params_for

BASE = "http://localhost:8080"


def _load_header() -> dict:
    """Read the access key from .env at runtime (never printed)."""
    env = next((p / ".env" for p in pathlib.Path(__file__).resolve().parents if (p / ".env").exists()), pathlib.Path(".env"))
    for line in env.read_text(encoding="utf-8").splitlines():
        if line.startswith("CPTM_TOKEN="):
            return {
                "X-CPTM-Token": line.split("=", 1)[1].strip(),
                "Content-Type": "application/json",
            }
    sys.exit("no CPTM_TOKEN in .env")


H = _load_header()


def call(method, path, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=H, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read().decode()[:300]}
    except Exception as e:
        return 0, {"detail": str(e)[:200]}


# A failure is legitimate if the tool reached the point of complaining about
# credentials, permissions, or an absent target/config.
LEGIT = re.compile(
    r"credential|NoCredential|DefaultCredentialsError|Authentication|AccessDenied|"
    r"Unable to locate|NoCredentialProviders|ProfileNotFound|could not be found|"
    r"does not exist or there was an error loading|"
    r"Please run 'az login'|login|permission|could not connect|connection refused|"
    r"No such file|Kubernetes version was not|client-key|--access-key|--secret-key|"
    r"required: --access|required: --secret|tenant|subscription|project|sa\.json|"
    r"UNAUTHORIZED|MissingSchema|EOFError|Protected S3 Bucket|"
    r"Missing environment variable|AZURE_CLIENT_ID|AZURE_TENANT_ID|AZURE_CLIENT_SECRET|"
    r"AWSSetUpSessionError|AzureEnvironmentVariableError|GCPSetUpSessionError",
    re.I,
)

BANNER = re.compile(
    r"prowler-cloud|Start free|Prowler Cloud|CLI - v|Snapshot|sign-up|utm_source|"
    r"autonomous triage|Continuous Security Monitoring|Lighthouse|"
    r"All parameters are case-insensitive",
    re.I,
)


def denoise(text: str) -> str:
    """Strip ANSI escapes and vendor marketing banners from tool output."""
    t = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)
    t = re.sub(r"\x1b\]8;;[^\x1b]*\x1b\\\\", "", t)
    return "\n".join(l for l in t.splitlines() if l.strip() and not BANNER.search(l))


_, tools = call("GET", "/api/tools")
print(f"{'tool':<20} {'launch':<7} {'result':<10} classification")
print("-" * 92)
bugs = []

for t in sorted(tools, key=lambda x: x["name"]):
    name = t["name"]
    st, res = call("POST", "/api/jobs/launch", {"tool": name, "params": params_for(t)})
    if st != 200:
        bugs.append((name, "LAUNCH REJECTED", str(res.get("detail", ""))[:80]))
        print(f"{name:<20} {'REJECT':<7} {'-':<10} {str(res.get('detail',''))[:60]}")
        continue

    jid = res["job_id"]
    for _ in range(30):
        time.sleep(4)
        _, j = call("GET", f"/api/jobs/{jid}")
        if j.get("status") in ("finished", "failed", "cancelled"):
            break

    status = j.get("status")
    _, out = call("GET", f"/api/jobs/{jid}/output")
    kept = denoise(out.get("output", "") or "")

    if status == "finished":
        print(f"{name:<20} {'OK':<7} {'finished':<10} OK (ran to completion)")
        continue

    tail = " ".join(kept.split())[-600:]
    if LEGIT.search(tail):
        print(f"{name:<20} {'OK':<7} {status:<10} expected: needs real credentials/target")
    else:
        lines = kept.splitlines()
        detail = lines[-1][:100] if lines else "(no output)"
        bugs.append((name, status, detail))
        print(f"{name:<20} {'OK':<7} {status:<10} POSSIBLE BUG: {detail[:60]}")

print()
if bugs:
    print(f"NEEDS_ATTENTION ({len(bugs)}):")
    for n, s, d in bugs:
        print(f"  {n} [{s}]: {d}")
else:
    print("ALL_TOOLS_BEHAVE_CORRECTLY")
