"""Check the Findings endpoint output for the most recent job of each tool."""
import json
import pathlib
import sys
import urllib.request

BASE = "http://localhost:8080"
env = pathlib.Path(__file__).resolve().parent / ".env"
H = {}
for line in env.read_text(encoding="utf-8").splitlines():
    if line.startswith("CPTM_TOKEN="):
        H = {"X-CPTM-Token": line.split("=", 1)[1].strip()}

with urllib.request.urlopen(
    urllib.request.Request(f"{BASE}/api/jobs?limit=60", headers=H)
) as r:
    jobs = json.loads(r.read().decode())

seen_tools = {}
for j in jobs:  # newest first
    if j["tool_name"] not in seen_tools:
        seen_tools[j["tool_name"]] = j

print(f"{'tool':<20} {'parser':<15} {'findings':<9} source")
print("-" * 70)
empty = []
for tool in sorted(seen_tools):
    j = seen_tools[tool]
    try:
        with urllib.request.urlopen(
            urllib.request.Request(f"{BASE}/api/jobs/{j['id']}/findings", headers=H)
        ) as r:
            f = json.loads(r.read().decode())
        n = len(f.get("findings", []))
        src = f.get("source", "-")
        parser = f.get("parser", "?")
        print(f"{tool:<20} {parser:<15} {n:<9} {src}")
        if n == 0:
            empty.append((tool, j["status"]))
    except Exception as e:
        print(f"{tool:<20} ERROR: {str(e)[:60]}")
        empty.append((tool, "error"))

print()
if empty:
    print(f"tools with 0 findings ({len(empty)}):")
    for t, s in empty:
        print(f"  {t} (job status: {s})")
else:
    print("ALL_TOOLS_PRODUCE_FINDINGS")
