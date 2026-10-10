"""Launch EVERY registered tool through the real API and report what happens.

This is the check that was missing: a tool can be listed, selectable and have a
valid template, yet still be impossible to launch. Each tool is launched with
plausible inputs and its immediate outcome recorded (no waiting for long scans).
"""
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

BASE = "http://localhost:8080"
env = next((p / ".env" for p in pathlib.Path(__file__).resolve().parents if (p / ".env").exists()), pathlib.Path(".env"))
TOKEN = next(
    (l.split("=", 1)[1].strip() for l in env.read_text().splitlines() if l.startswith("CPTM_TOKEN=")),
    "",
)
H = {"X-CPTM-Token": TOKEN, "Content-Type": "application/json"}


def call(method, path, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=H, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"detail": e.read().decode()[:200]}
    except Exception as e:
        return 0, {"detail": str(e)[:200]}


_, tools = call("GET", "/api/tools")

# Plausible inputs per tool so the template renders. Values point at public or
# local targets, or at a deliberately absent credential, so nothing destructive
# or billable happens.
INPUTS = {
    "nmap": {"target": "127.0.0.1", "flags": "-sT -Pn -p 8080"},
    "trivy-image": {"scan_type": "image", "target": "alpine:3.19", "extra_args": "--quiet"},
    "prowler-aws": {"profile": "default", "region": "us-east-1"},
    "prowler-azure": {"subscription": ""},
    "prowler-gcp": {"project": ""},
    "scoutsuite-aws": {"profile": "default"},
    "scoutsuite-azure": {},
    "scoutsuite-gcp": {"project": "example-project"},
    "cloud-enum": {"keyword": "flaws"},
    "cloudbrute": {"keyword": "flaws", "domain": "cloud"},
    "cloudfox": {},
    "enumerate-iam": {},
    "pmapper": {"profile": "default"},
    "pacu": {},
    "roadrecon-azure": {"username": "user@example.com", "password": "x"},
    "gcp-scanner": {},
    "kube-hunter": {"target": "127.0.0.1", "mode": ""},
    "kube-bench": {},
    "microburst-azure": {"keyword": "example"},
}

print(f"Launching {len(tools)} tools through the API\n")
print(f"{'tool':<20} {'launch':<8} {'status':<10} note")
print("-" * 78)
results = {}
for t in sorted(tools, key=lambda x: x["name"]):
    name = t["name"]
    params = INPUTS.get(name, {})
    st, res = call("POST", "/api/jobs/launch", {"tool": name, "params": params})
    if st != 200:
        results[name] = ("REJECTED", res.get("detail", "")[:60])
        print(f"{name:<20} {'REJECT':<8} {'-':<10} {res.get('detail','')[:50]}")
        continue
    jid = res["job_id"]
    # Give it a moment, then record its state without waiting for a full scan.
    time.sleep(6)
    _, j = call("GET", f"/api/jobs/{jid}")
    status = j.get("status", "?")
    err = (j.get("error") or "")[:50]
    results[name] = (status, err)
    print(f"{name:<20} {'OK':<8} {status:<10} {err}")

print()
bad = {k: v for k, v in results.items() if v[0] == "REJECTED"}
print(f"launched successfully: {len(results) - len(bad)}/{len(results)}")
if bad:
    print("REJECTED (cannot be launched at all):")
    for k, v in bad.items():
        print(f"  {k}: {v[1]}")
    sys.exit(1)
print("ALL_TOOLS_LAUNCHABLE")
