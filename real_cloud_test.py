"""Real-cloud test pass against the running CPTM stack.

Two kinds of test:
  A. Recon tools against intentionally-public cloud training infrastructure
     (flaws.cloud exists for exactly this purpose).
  B. Credential plumbing: prove the cloud posture tools receive mounted creds
     and fail cleanly when none are supplied.

Token is read from .env at runtime and never printed.
"""
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

BASE = "http://localhost:8080"

env = pathlib.Path(__file__).resolve().parent / ".env"
TOKEN = next(
    (l.split("=", 1)[1].strip() for l in env.read_text().splitlines() if l.startswith("CPTM_TOKEN=")),
    "",
)
HEADERS = {"X-CPTM-Token": TOKEN, "Content-Type": "application/json"}


def call(method, path, body=None, timeout=90):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"__error": e.code, "detail": e.read().decode()[:400]}
    except Exception as e:
        return {"__error": "exc", "detail": str(e)[:200]}


def run_tool(tool, params, wait_s=180, label=""):
    """Launch a tool and block until it finishes. Returns (job, output)."""
    print(f"\n--- {label or tool} ---")
    res = call("POST", "/api/jobs/launch", {"tool": tool, "params": params})
    if "__error" in res:
        print("  LAUNCH FAILED:", res)
        return None, ""
    jid = res["job_id"]
    print(f"  job #{jid} launched")
    deadline = time.time() + wait_s
    while time.time() < deadline:
        time.sleep(5)
        j = call("GET", f"/api/jobs/{jid}")
        if j.get("status") in ("finished", "failed", "cancelled"):
            out = call("GET", f"/api/jobs/{jid}/output").get("output", "")
            print(f"  status={j['status']} exit={j.get('exit_code')} artifacts={len(j.get('artifacts', []))}")
            if j.get("error"):
                print("  error:", j["error"][:300])
            return j, out
    print("  TIMEOUT")
    return None, ""


print("=" * 70)
print("A. RECON AGAINST REAL PUBLIC CLOUD INFRASTRUCTURE")
print("=" * 70)

# cloud_enum performs passive OSINT: DNS lookups + HTTP requests to check for
# public storage/app endpoints. flaws.cloud is a public AWS training target.
j, out = run_tool("cloud-enum", {"keyword": "flaws"}, wait_s=240, label="cloud_enum (flaws)")
print("  " + "\n  ".join([l for l in out.splitlines() if l.strip()][:15]))

# CloudBrute enumerates public bucket/blob names for a domain.
j, out = run_tool(
    "cloudbrute",
    {"keyword": "flaws", "domain": "cloud", "extra_args": "-t 20"},
    wait_s=240,
    label="CloudBrute (flaws / cloud)",
)
print("  " + "\n  ".join([l for l in out.splitlines() if l.strip()][:15]))

print()
print("=" * 70)
print("B. CREDENTIAL PLUMBING (no cloud creds mounted on this host)")
print("=" * 70)

# Prowler needs real AWS creds. Without them it must fail cleanly with a clear
# auth error - proving the credential path is wired and reachable from the
# job container, rather than hanging or silently succeeding.
j, out = run_tool("prowler-aws", {"profile": "default", "regions": "us-east-1"}, wait_s=180, label="Prowler AWS (expect clean auth failure)")
lines = [l for l in out.splitlines() if l.strip()]
print("  " + "\n  ".join(lines[-8:]))

print()
print("=" * 70)
print("C. REAL IMAGE SCAN (public registry)")
print("=" * 70)
j, out = run_tool("trivy-image", {"scan_type": "image", "target": "nginx:1.27-alpine", "extra_args": "--quiet --timeout 5m"}, wait_s=300, label="Trivy nginx:1.27-alpine")
if j:
    f = call("GET", f"/api/jobs/{j['id']}/findings")
    print("  parser:", f.get("parser"), "source:", f.get("source"))
    print("  total:", f.get("summary", {}).get("total_findings"), "severity:", f.get("summary", {}).get("by_severity"))

print("\nREAL_CLOUD_TEST_DONE")
