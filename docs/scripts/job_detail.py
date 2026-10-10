"""Inspect the final result of one tool's most recent job (PS-safe)."""
import json
import pathlib
import re
import sys
import urllib.request

BASE = "http://localhost:8080"
env = next((p / ".env" for p in pathlib.Path(__file__).resolve().parents if (p / ".env").exists()), pathlib.Path(".env"))
H = {}
for line in env.read_text(encoding="utf-8").splitlines():
    if line.startswith("CPTM_TOKEN="):
        H = {"X-CPTM-Token": line.split("=", 1)[1].strip()}

tool = sys.argv[1] if len(sys.argv) > 1 else "cloud-enum"
with urllib.request.urlopen(urllib.request.Request(f"{BASE}/api/jobs?limit=40", headers=H)) as r:
    jobs = json.loads(r.read().decode())
job = next((j for j in jobs if j["tool_name"] == tool), None)
if not job:
    sys.exit(f"no job for {tool}")

req = urllib.request.Request(f"{BASE}/api/jobs/{job['id']}/output", headers=H)
with urllib.request.urlopen(req, timeout=60) as r:
    out = json.loads(r.read().decode())["output"]

text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", out)
print(f"job #{job['id']} {tool}: status={job['status']} exit={job['exit_code']}")
print("-" * 70)
interesting = [
    l for l in text.splitlines()
    if re.search(r"amazonaws|blob|storage|googleapis|FOUND|\[\+\]|\[-\]|Protected|Open|bucket", l, re.I)
]
print("\n".join(interesting[-20:]) if interesting else "(no matching lines)")
