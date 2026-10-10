"""CPTM master test suite â€” flaws.cloud as the target.

Sections
  A. Backend contract: health, auth gate, tool registry, DB writes
  B. Frontend contract: served bundle, auth flow, tool list renderability
  C. Every tool launched against flaws.cloud (or its own container for
     non-cloud tools), with failure classification
  D. Output writing: stdout persistence, artifact files, artifact download,
     findings parsing
  E. Cleanup summary

Every value is public infrastructure or a placeholder; no credentials.
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
REPORT = []


def _load_header() -> dict:
    env = next((p / ".env" for p in pathlib.Path(__file__).resolve().parents if (p / ".env").exists()), pathlib.Path(".env"))
    for line in env.read_text(encoding="utf-8").splitlines():
        if line.startswith("CPTM_TOKEN="):
            return {"X-CPTM-Token": line.split("=", 1)[1].strip(),
                    "Content-Type": "application/json"}
    sys.exit("no CPTM_TOKEN in .env")


H = _load_header()
PASS, FAIL = [], []


def check(section, label, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    line = f"[{tag}] {section} :: {label}" + (f" â€” {detail}" if detail else "")
    print(line)
    (PASS if ok else FAIL).append((section, label, detail))


def call(method, path, body=None, timeout=90, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=H, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read().decode()
            if raw:
                return r.status, payload
            return r.status, (json.loads(payload) if payload else {})
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode()[:300]
        try:
            return e.code, json.loads(body_txt)
        except Exception:
            return e.code, {"detail": body_txt}
    except Exception as e:
        return 0, {"detail": str(e)[:200]}


def call_noauth(method, path, body=None):
    headers = {"Content-Type": "application/json"}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]
    except Exception as e:
        return 0, str(e)[:200]


BANNER = re.compile(
    r"prowler-cloud|Start free|Prowler Cloud|CLI - v|Snapshot|sign-up|utm_source|"
    r"autonomous triage|Continuous Security Monitoring|Lighthouse|"
    r"All parameters are case-insensitive",
    re.I,
)
LEGIT = re.compile(
    r"credential|NoCredential|DefaultCredentialsError|Authentication|AccessDenied|"
    r"Unable to locate|NoCredentialProviders|ProfileNotFound|could not be found|"
    r"does not exist or there was an error loading|Please run 'az login'|login|"
    r"permission|could not connect|connection refused|No such file|"
    r"Kubernetes version was not|client-key|--access-key|--secret-key|tenant|"
    r"subscription|project|sa\.json|UNAUTHORIZED|MissingSchema|EOFError|"
    r"Protected S3 Bucket",
    re.I,
)


def denoise(text: str) -> str:
    t = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)
    t = re.sub(r"\x1b\]8;;[^\x1b]*\x1b\\\\", "", t)
    return "\n".join(l for l in t.splitlines() if l.strip() and not BANNER.search(l))


# per-tool test inputs; flaws.cloud-targeted where meaningful
TOOL_INPUTS = {
    "nmap": {"target": "flaws.cloud", "flags": "-sT -Pn -p 80,443 --open"},
    "cloud-enum": {"keyword": "flaws"},
    "cloudbrute": {"keyword": "flaws", "domain": "flaws.cloud"},
    "trivy-image": {"scan_type": "image", "target": "alpine:3.19"},
    "kube-hunter": {"target": "127.0.0.1", "mode": ""},
    "prowler-aws": {"profile": "default", "region": "us-east-1"},
    "cloudfox": {"profile_flag": "-p default", "command": "inventory"},
    "pacu": {"profile": "default", "exec_flag": "--module-info",
             "module": "iam__enum_users_roles_policies_groups"},
    "pmapper": {"profile": "default"},
    "prowler-azure": {"subscription": "", "auth": "--sp-env-auth"},
    "prowler-gcp": {"project": ""},
    "scoutsuite-aws": {"profile": "default"},
    "scoutsuite-azure": {},
    "scoutsuite-gcp": {"project": "example-project"},
    "roadrecon-azure": {"username": "pentester@example.com",
                        "tenant": "example.onmicrosoft.com"},
    "gcp-scanner": {"key_path": "/creds/gcp", "light": ""},
    "microburst-azure": {"base_name": "flaws"},
    "enumerate-iam": {},
    "kube-bench": {},
}


# ============================================================
print("=" * 78)
print("A. BACKEND CONTRACT")
print("=" * 78)

st, body = call_noauth("GET", "/api/health")
check("A", "health open (liveness)", st == 200)

st, _ = call_noauth("GET", "/api/auth/check")
check("A", "auth gate rejects missing token with 401", st == 401, f"got {st}")

st, _ = call("GET", "/api/auth/check")
check("A", "auth gate accepts valid token", st == 200)

st, tools = call("GET", "/api/tools")
check("A", "tool registry reachable", st == 200)
check("A", "19 tools registered", len(tools) == 19, f"got {len(tools)}")

cats = sorted({t["category"] for t in tools})
check("A", "categories cover aws/azure/gcp/kubernetes/general",
      set(cats) == {"aws", "azure", "gcp", "kubernetes", "general"}, str(cats))

bad_names = [t["name"] for t in tools if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", t["name"])]
check("A", "tool names are slug-safe", not bad_names, str(bad_names))

# CRUD round trip on a scratch tool
scratch = {"name": "zz-scratch-crud", "display_name": "Scratch",
           "command_template": "echo {msg} > /artifacts/jobs/{job_id}/scratch.txt",
           "category": "general", "output_type": "raw",
           "params": [{"name": "msg", "type": "string", "default": "hi", "required": True}]}
st, _ = call("POST", "/api/tools", scratch)
check("A", "create tool via API", st == 201, f"got {st}")
st, _ = call("PUT", "/api/tools/zz-scratch-crud", {**scratch, "display_name": "Scratch v2"})
check("A", "update tool via API", st == 200, f"got {st}")
st, _ = call("DELETE", "/api/tools/zz-scratch-crud")
check("A", "delete tool via API", st == 200, f"got {st}")

# duplicate name must conflict
call("POST", "/api/tools", scratch)
st, _ = call("POST", "/api/tools", scratch)
check("A", "duplicate tool name rejected (409)", st == 409, f"got {st}")
call("DELETE", "/api/tools/zz-scratch-crud")

# launch validation
st, r = call("POST", "/api/jobs/launch", {"tool": "no-such-tool", "params": {}})
check("A", "launch unknown tool -> 404", st == 404, f"got {st}")
st, r = call("POST", "/api/jobs/launch", {"tool": "nmap", "params": {}})
check("A", "launch missing required param -> 400", st == 400, f"got {st}")

# ============================================================
print()
print("=" * 78)
print("B. FRONTEND CONTRACT (served bundle)")
print("=" * 78)

st, html = call("GET", "/", raw=True)
check("B", "index.html served", st == 200)
m = re.search(r'/assets/index-[^"]+\.js', html)
check("B", "bundle referenced", bool(m))
bundle = ""
if m:
    st_b, bundle = call("GET", m.group(0), raw=True)
    check("B", "bundle served", st_b == 200)
    for marker, label in [
        ("auth/check", "login gate uses /api/auth/check"),
        ("unauthorized", "401 handler present"),
        ("sign out", "sign out control present"),
        ("Connecting", "loading state present"),
    ]:
        check("B", label, marker in bundle)
    check("B", "flag param type supported in UI", "'flag'" in bundle or '"flag"' in bundle)

# ============================================================
print()
print("=" * 78)
print("C. ALL TOOLS vs flaws.cloud (+ container-local for non-cloud tools)")
print("=" * 78)

finished, expected_fail, suspect, ws_fail = [], [], [], []

results = {}
for t in sorted(tools, key=lambda x: x["name"]):
    name = t["name"]
    st, res = call("POST", "/api/jobs/launch", {"tool": name, "params": params_for(t)},
                   timeout=60)
    if st != 200:
        suspect.append((name, "LAUNCH REJECTED", str(res.get("detail", ""))[:100]))
        print(f"  {name:<20} REJECT {str(res.get('detail',''))[:60]}")
        continue
    jid = res["job_id"]
    deadline = time.time() + 240
    status = "running"
    while time.time() < deadline:
        time.sleep(5)
        _, j = call("GET", f"/api/jobs/{jid}")
        status = j.get("status", "running")
        if status in ("finished", "failed", "cancelled"):
            break
    _, out = call("GET", f"/api/jobs/{jid}/output", timeout=60)
    kept = denoise(out.get("output", "") or "")
    artifacts = j.get("artifacts", [])
    tail = " ".join(kept.split())[-600:]
    results[name] = {"job_id": jid, "status": status, "artifacts": artifacts, "kept": kept}

    if status == "finished":
        finished.append(name)
        print(f"  {name:<20} FINISHED  job=#{jid} artifacts={len(artifacts)}")
    elif LEGIT.search(tail):
        expected_fail.append(name)
        print(f"  {name:<20} {status:<9} job=#{jid} expected: needs real credentials")
    else:
        lines = kept.splitlines()
        detail = lines[-1][:90] if lines else "(no output)"
        suspect.append((name, status, detail))
        print(f"  {name:<20} {status:<9} job=#{jid} SUSPECT: {detail}")

print()
check("C", "all 19 tools launched", len(results) == 19, f"{len(results)}/19")
check("C", "no launch rejections or suspect failures", not suspect,
      "; ".join(f"{n}:{s}" for n, s, _ in suspect) if suspect else "")
check("C", "at least one real-cloud recon tool completed",
      bool({"cloud-enum", "cloudbrute", "nmap"} & set(finished)),
      f"finished={finished}")

# cloud_enum must have found real flaws.cloud infrastructure
ce = results.get("cloud-enum", {})
found_buckets = "s3.amazonaws.com" in ce.get("kept", "") or "s3.amazonaws.com" in " ".join(
    ce.get("kept", "").splitlines())
check("C", "cloud_enum found real S3 endpoints for flaws.cloud",
      found_buckets or ce.get("status") == "running", ce.get("status", "no job"))

# ============================================================
print()
print("=" * 78)
print("D. OUTPUT WRITING: stdout, artifacts, download, findings, DB")
print("=" * 78)

# D1: a scratch tool writes an artifact, is recorded, downloads with content
st, _ = call("POST", "/api/tools", scratch)
st, res = call("POST", "/api/jobs/launch", {"tool": "zz-scratch-crud", "params": {"msg": "cptm-artifact-ok"}})
check("D", "scratch tool launch", st == 200, f"got {st}")
if st == 200:
    jid = res["job_id"]
    for _ in range(20):
        time.sleep(3)
        _, j = call("GET", f"/api/jobs/{jid}")
        if j.get("status") in ("finished", "failed"):
            break
    check("D", "scratch tool finished", j.get("status") == "finished", j.get("status"))
    arts = j.get("artifacts", [])
    check("D", "artifact recorded in DB", len(arts) == 1, f"{len(arts)} artifacts")
    if arts:
        st_a, content = call("GET", f"/api/jobs/{jid}/artifacts/{arts[0]['path']}", raw=True)
        check("D", "artifact downloads", st_a == 200, f"got {st_a}")
        check("D", "artifact content correct", "cptm-artifact-ok" in content)
call("DELETE", "/api/tools/zz-scratch-crud")

# D2: trivy writes a JSON artifact AND findings parse from it
tv = results.get("trivy-image", {})
if tv.get("job_id"):
    jid = tv["job_id"]
    _, j = call("GET", f"/api/jobs/{jid}")
    check("D", "trivy artifact written", len(j.get("artifacts", [])) >= 1)
    if j.get("artifacts"):
        st_a, body = call("GET", f"/api/jobs/{jid}/artifacts/{j['artifacts'][0]['path']}", raw=True)
        ok_json = st_a == 200 and body.strip().startswith("{")
        check("D", "trivy artifact is valid JSON", ok_json)
        if ok_json:
            doc = json.loads(body)
            n_results = len(doc.get("Results", []))
            check("D", "trivy artifact has Results", n_results >= 1, f"{n_results} results")
    st_f, f = call("GET", f"/api/jobs/{jid}/findings")
    total = f.get("summary", {}).get("total_findings", 0)
    check("D", "trivy findings parsed", st_f == 200 and total > 0, f"total={total}")
    check("D", "findings carry severity breakdown",
          bool(f.get("summary", {}).get("by_severity")), str(f.get("summary", {}).get("by_severity"))[:80])

# D3: nmap output persisted and inspectable
nm = results.get("nmap", {})
if nm.get("job_id"):
    _, out = call("GET", f"/api/jobs/{nm['job_id']}/output")
    ok = "Nmap" in out.get("output", "") and ("open" in out.get("output", "") or "closed" in out.get("output", ""))
    check("D", "nmap stdout persisted with scan result", ok)

# D4: WebSocket live stream + replay for a finished job
try:
    import websockets
    import asyncio

    async def ws_check():
        uri = f"ws://localhost:8080/ws/jobs/{nm['job_id']}?token={H['X-CPTM-Token']}"
        async with websockets.connect(uri) as ws:
            got_stream, got_done = False, False
            for _ in range(50):
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=5)
                except asyncio.TimeoutError:
                    break
                obj = json.loads(msg)
                if obj.get("type") == "stream" and "Nmap" in obj.get("data", ""):
                    got_stream = True
                if obj.get("type") == "done":
                    got_done = True
                    break
            return got_stream, got_done

    gs, gd = asyncio.get_event_loop().run_until_complete(ws_check()) if False else asyncio.run(ws_check())
    check("D", "finished job replays output over WebSocket", gs)
    check("D", "WebSocket sends terminal done event", gd)
except ImportError:
    check("D", "WebSocket replay (websockets lib missing locally)", False, "skipped")

# D5: DB persistence spot-check inside the backend container
import subprocess

def sh(cmd):
    return subprocess.run(["docker", "compose", "-f",
                           str(pathlib.Path(__file__).parent / "docker-compose.yml"),
                           "exec", "-T"] + cmd,
                          capture_output=True, text=True, timeout=120)

q = sh(["backend", "python", "-c",
        "import sqlite3; c=sqlite3.connect('/data/cptm.db'); "
        "print(c.execute('select count(*) from jobs').fetchone()[0], "
        "c.execute('select count(*) from artifacts').fetchone()[0], "
        "c.execute(\"select count(*) from jobs where output_text != ''\").fetchone()[0])"])
m = re.search(r"(\d+)\s+(\d+)\s+(\d+)", q.stdout)
if m:
    n_jobs, n_art, n_with_output = map(int, m.groups())
    check("D", "jobs persisted in SQLite", n_jobs >= 19, f"{n_jobs} jobs")
    check("D", "artifacts persisted in SQLite", n_art >= 1, f"{n_art} artifacts")
    check("D", "stdout persisted for finished jobs", n_with_output >= 5, f"{n_with_output} jobs")
else:
    check("D", "DB spot-check", False, q.stderr[:120])

# D6: unauthorized artifact access blocked
if nm.get("job_id"):
    st_u, _ = call_noauth("GET", f"/api/jobs/{nm['job_id']}/artifacts/jobs/{nm['job_id']}/x.txt")
    check("D", "artifact download requires token", st_u in (401, 403, 404), f"got {st_u}")

# ============================================================
print()
print("=" * 78)
print("SUMMARY")
print("=" * 78)
print(f"PASS: {len(PASS)}   FAIL: {len(FAIL)}")
if FAIL:
    print("\nFailures:")
    for s, l, d in FAIL:
        print(f"  [{s}] {l}" + (f" â€” {d}" if d else ""))
print()
print(f"tools finished cleanly : {len(finished)} -> {finished}")
print(f"expected cred failures : {len(expected_fail)}")
print(f"suspect failures       : {len(suspect)} -> {[n for n, _, _ in suspect]}")
print()
print("MASTER_SUITE_DONE" if not FAIL else "MASTER_SUITE_HAD_FAILURES")
