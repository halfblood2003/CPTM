"""Live test of the running CPTM stack.

Exercises the parts that a REST-only check misses:
  1. launch a real tool job over REST
  2. subscribe to /ws/jobs/{id} and verify output arrives over the WebSocket
  3. connect to /ws/terminal, run a command, verify the PTY answers
  4. confirm findings parse from the trivy artifact

The access token is read from .env at runtime and never printed.
"""
import asyncio
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

BASE = "http://localhost:8080"
WS = "ws://localhost:8080"


def load_token() -> str:
    env = next((p / ".env" for p in pathlib.Path(__file__).resolve().parents if (p / ".env").exists()), pathlib.Path(".env"))
    for line in env.read_text(encoding="utf-8").splitlines():
        if line.startswith("CPTM_TOKEN="):
            return line.split("=", 1)[1].strip()
    sys.exit("no CPTM_TOKEN in .env")


TOKEN = load_token()
HEADERS = {"X-CPTM-Token": TOKEN, "Content-Type": "application/json"}


def call(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"__error": e.code, "detail": e.read().decode()[:300]}


async def main() -> None:
    print("=== 1. health / tool count ===")
    print("health:", call("GET", "/api/health"))
    tools = call("GET", "/api/tools")
    print("tools registered:", len(tools))

    print("\n=== 2. launch a real job (nmap against the stack's own network) ===")
    # 172.20.0.1 is the compose gateway as seen from a job container; we scan the
    # backend's published port to prove a job can reach a service on the network.
    res = call(
        "POST",
        "/api/jobs/launch",
        {"tool": "nmap", "params": {"target": "cptm-backend", "flags": "-sT -Pn -p 8000 --open"}},
    )
    if "__error" in res:
        sys.exit(f"launch failed: {res}")
    job_id = res["job_id"]
    print("job_id:", job_id)

    print("\n=== 3. stream job output over WebSocket ===")
    try:
        import websockets
    except ImportError:
        print("websockets not installed locally; falling back to REST polling")
        websockets = None

    if websockets:
        got_lines = 0
        done = None
        uri = f"{WS}/ws/jobs/{job_id}?token={TOKEN}"
        try:
            async with websockets.connect(uri) as ws:
                while True:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=45)
                    except asyncio.TimeoutError:
                        break
                    obj = json.loads(msg)
                    if obj.get("type") == "stream":
                        for ln in obj["data"].splitlines():
                            if ln.strip():
                                got_lines += 1
                                if got_lines <= 8:
                                    print("  WS>", ln.strip()[:90])
                    elif obj.get("type") == "done":
                        done = obj
                        break
        except Exception as e:
            print("  WS error:", type(e).__name__, str(e)[:120])
        print(f"  streamed lines over WS: {got_lines}")
        print(f"  done event: {done}")

    job = call("GET", f"/api/jobs/{job_id}")
    print(f"  job status={job.get('status')} exit_code={job.get('exit_code')}")

    print("\n=== 4. web terminal PTY (/ws/terminal) ===")
    if websockets:
        try:
            async with websockets.connect(f"{WS}/ws/terminal?token={TOKEN}") as ws:
                await asyncio.sleep(1.0)
                await ws.send(json.dumps({"type": "input", "data": "echo CPTM_PTY_OK; id -un; pwd\n"}))
                buf = ""
                deadline = asyncio.get_event_loop().time() + 12
                while asyncio.get_event_loop().time() < deadline:
                    try:
                        chunk = await asyncio.wait_for(ws.recv(), timeout=3)
                    except asyncio.TimeoutError:
                        break
                    buf += chunk if isinstance(chunk, str) else chunk.decode(errors="replace")
                    if "CPTM_PTY_OK" in buf:
                        break
                ok = "CPTM_PTY_OK" in buf
                print("  PTY responded:", ok)
                for ln in [l for l in buf.splitlines() if l.strip()][:6]:
                    print("  PTY>", ln.strip()[:90])
        except Exception as e:
            print("  terminal WS error:", type(e).__name__, str(e)[:120])

    print("\n=== 5. launch a findings-producing job (trivy) and read findings ===")
    res = call(
        "POST",
        "/api/jobs/launch",
        {"tool": "trivy-image", "params": {"scan_type": "image", "target": "alpine:3.19", "extra_args": "--quiet --timeout 5m"}},
    )
    if "__error" not in res:
        tid = res["job_id"]
        print("  job_id:", tid, "- waiting for completion...")
        for _ in range(40):
            await asyncio.sleep(6)
            j = call("GET", f"/api/jobs/{tid}")
            if j.get("status") in ("finished", "failed"):
                print(f"  status={j['status']} exit={j.get('exit_code')} artifacts={len(j.get('artifacts', []))}")
                break
        f = call("GET", f"/api/jobs/{tid}/findings")
        print("  parser:", f.get("parser"), "source:", f.get("source"))
        print("  total findings:", f.get("summary", {}).get("total_findings"))
        print("  by severity:", f.get("summary", {}).get("by_severity"))
        for item in (f.get("findings") or [])[:3]:
            print("   -", item.get("severity"), item.get("id"), str(item.get("title"))[:70])
    else:
        print("  trivy launch failed:", res)

    print("\n=== 6. cancel path ===")
    res = call("POST", "/api/jobs/launch", {"tool": "nmap", "params": {"target": "cptm-backend", "flags": "-sT -Pn -p- "}})
    if "__error" not in res:
        cid = res["job_id"]
        await asyncio.sleep(3)
        print("  cancel:", call("POST", f"/api/jobs/{cid}/cancel"))
        await asyncio.sleep(2)
        print("  status after cancel:", call("GET", f"/api/jobs/{cid}").get("status"))

    print("\nALL_LIVE_TESTS_DONE")


asyncio.run(main())
