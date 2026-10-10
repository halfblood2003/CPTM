"""Show the real failure reason for a given tool's most recent job."""
import json
import pathlib
import re
import sys
import urllib.request

BASE = "http://localhost:8080"
env = next((p / ".env" for p in pathlib.Path(__file__).resolve().parents if (p / ".env").exists()), pathlib.Path(".env"))
TOKEN = next(
    (l.split("=", 1)[1].strip() for l in env.read_text().splitlines() if l.startswith("CPTM_TOKEN=")),
    "",
)
H = {"X-CPTM-Token": TOKEN}

tool = sys.argv[1] if len(sys.argv) > 1 else "prowler-aws"

with urllib.request.urlopen(
    urllib.request.Request(f"{BASE}/api/jobs?limit=40", headers=H)
) as r:
    jobs = json.loads(r.read().decode())

job = next((j for j in jobs if j["tool_name"] == tool), None)
if not job:
    sys.exit(f"no jobs found for {tool}")

with urllib.request.urlopen(
    urllib.request.Request(f"{BASE}/api/jobs/{job['id']}/output", headers=H)
) as r:
    out = json.loads(r.read().decode())["output"]

print(f"job #{job['id']} {tool}: status={job['status']} exit={job['exit_code']}")
print(f"command: {job['command']}")
print("-" * 70)

# Strip ANSI escapes and Prowler's marketing banner so the real error shows.
text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", out)
text = re.sub(r"\x1b\]8;;[^\x1b]*\x1b\\\\", "", text)
DROP = re.compile(
    r"prowler-cloud|Start free|Prowler Cloud|CLI - v|_ __|/\s*__|\\\\__|"
    r"^\s*[â”‚|]\s*$|^\s*[â”‚|]|Snapshot|sign-up|utm_source|"
    r"autonomous triage|Continuous Security|Triage|Lighthouse",
    re.I,
)
lines = [
    l.strip()
    for l in text.splitlines()
    if l.strip() and not DROP.search(l)
]
print("\n".join(lines[-25:]))
