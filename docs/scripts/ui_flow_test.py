"""Simulate the exact browser flow the user reported as broken.

Reproduces what the React app does, in order:
  1. load the page
  2. call /api/auth/check with NO token  -> must be 401 (login screen shows)
  3. call /api/auth/check with the right token -> must be 200
  4. fetch the tool list (this is what populates the launcher dropdown)
  5. launch a job the way the Launch form does
This is the path that silently failed before, leaving an empty unselectable UI.
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

failures = []


def hit(path, token=None, method="GET", body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-CPTM-Token"] = token
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, None


def check(label, condition, detail=""):
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}{(' â€” ' + detail) if detail else ''}")
    if not condition:
        failures.append(label)


print("=== STEP 1: load page ===")
try:
    with urllib.request.urlopen(BASE + "/", timeout=20) as r:
        html = r.read().decode()
    check("index.html served", r.status == 200)
    import re

    js = re.search(r"/assets/index-[^\"]+\.js", html)
    check("bundle referenced", bool(js), js.group(0) if js else "")
except Exception as e:
    check("index.html served", False, str(e))

print("\n=== STEP 2: no token -> must be 401 (shows login) ===")
status, _ = hit("/api/auth/check")
check("auth/check without token is 401", status == 401, f"got {status}")

print("\n=== STEP 3: wrong token -> must be 401 ===")
status, _ = hit("/api/auth/check", token="definitely-not-the-token")
check("auth/check with wrong token is 401", status == 401, f"got {status}")

print("\n=== STEP 4: correct token -> must be 200 ===")
status, body = hit("/api/auth/check", token=TOKEN)
check("auth/check with real token is 200", status == 200, f"got {status} {body}")

print("\n=== STEP 5: tool list populates the launcher ===")
status, tools = hit("/api/tools", token=TOKEN)
check("tool list reachable", status == 200, f"got {status}")
check("tool list non-empty", bool(tools), f"{len(tools) if tools else 0} tools")

if tools:
    cats = sorted({t["category"] for t in tools})
    print(f"    categories: {cats}")
    # Every tool must have a selectable label and a runnable template.
    bad = [t["name"] for t in tools if not t.get("display_name") or not t.get("command_template")]
    check("every tool has display_name + template", not bad, str(bad))
    # Every param must expose a type the UI knows how to render.
    known = {"string", "bool", "select", "flag"}
    odd = [
        (t["name"], p["name"], p.get("type"))
        for t in tools
        for p in t.get("params", [])
        if p.get("type") not in known
    ]
    check("all param types renderable by the UI", not odd, str(odd))

print("\n=== STEP 6: launch each tool briefly (dry validation of the form path) ===")
# Launch one harmless job to prove the form -> launch path works end to end.
status, res = hit("/api/jobs/launch", token=TOKEN, method="POST",
                  body={"tool": "nmap", "params": {"target": "127.0.0.1", "flags": "-sT -Pn -p 8080"}})
check("launch accepted", status == 200, f"got {status} {res}")
if status == 200:
    jid = res["job_id"]
    for _ in range(20):
        time.sleep(3)
        st, j = hit(f"/api/jobs/{jid}", token=TOKEN)
        if j and j.get("status") in ("finished", "failed", "cancelled"):
            break
    check("job completed", j.get("status") == "finished", f"status={j.get('status')}")
    st, out = hit(f"/api/jobs/{jid}/output", token=TOKEN)
    check("job produced output", bool(out.get("output", "").strip()))

print()
if failures:
    print(f"UI_FLOW_FAILURES ({len(failures)}): {failures}")
    sys.exit(1)
print("UI_FLOW_ALL_PASS")
