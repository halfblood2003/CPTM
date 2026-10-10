# Cloud Pentest Tool Manager (CPTM)

A single web-based manager for cloud pentest tools across AWS, Azure, GCP, and Kubernetes.
Every tool runs in an isolated Docker container; live output streams into the GUI; results
and artifacts are collected per job; a full web terminal is included; and you can register
new tools from the GUI — no code changes, no rebuilds.

> Use only against systems you are explicitly authorized to test. You supply your own
> engagement credentials; CPTM never bakes credentials into images.

## Architecture

```
 Browser (React + xterm.js)
    │  REST (tool CRUD, job control)   WebSocket (live output, terminal PTY)
    ▼
 FastAPI backend (async)  ── Docker SDK ──▶  per-tool job containers
    │                                            │
    │                                     named volumes:
    ├─ SQLite: tools, jobs, findings            ├─ cptm-workspace (shared FS)
    ├─ parsers: Prowler/ScoutSuite JSON         └─ cptm-artifacts (results)
    └─ toolbox container (fat image, all curated tools, interactive shell)
```

Why this stack:
- **FastAPI (async)**: pentest jobs are long-running, I/O-heavy processes. Async streaming
  handles dozens of concurrent tool containers with minimal overhead.
- **Docker-per-job**: isolation, reproducibility, and the ability to run tools that need
  conflicting Python/Node/runtime versions side by side.
- **Toolbox image**: one fat image with all curated tools preinstalled for instant launch and
  a shared credential cache; per-tool images remain possible via the tool registry.
- **SQLite**: single-operator tooling doesn't need a database server; zero config, fast.
- **WebSocket + xterm.js**: low-latency live output and a real interactive PTY in the browser.

## Quick start

```bash
cd cloud-pentest-manager

# 1. Set your access token (required — no default shipped)
cp .env.example .env
python -c "import secrets; print('CPTM_TOKEN=' + secrets.token_urlsafe(32))" >> .env

# 2. Build the frontend (or keep the prebuilt dist/)
cd frontend && npm install && npm run build && cd ..

# 3. Build and start
docker compose build
docker compose up -d
```

Open http://localhost:8080 — the backend serves the built frontend on a single port.
Enter the token from your `.env` when prompted (stored in localStorage).

## Layout

- `backend/` — FastAPI app (routers, services, parsers, DB models)
- `frontend/` — React + Vite app
- `tools/` — seeded tool specs (YAML), loaded into the registry at startup
- `toolbox/` — Dockerfile for the fat all-tools image
- `docker-compose.yml` — backend + toolbox + volumes

## Using it

1. **Prepare credentials** — see `.env.example` and `credentials/README.md`. The
   container already points at:
   - `/creds/aws/credentials` + `/creds/aws/config` (AWS)
   - `/creds/gcp/sa.json` (GCP service-account key)
   - Azure service principal via env vars, or `az login` in the web Terminal
2. **Launch a tool** — Dashboard → click any tool, or Launch → pick from the dropdown.
   The form is generated from the tool's parameter schema; hit Run.
3. **Findings** — tools with structured output (Prowler, ScoutSuite, Trivy,
   kube-hunter, kube-bench) are parsed automatically into a severity-tagged table.
   The parser reads the tool's **report artifact** first, falling back to stdout.
4. **Artifacts** — anything written to `/artifacts/jobs/<id>/` appears under the job
   and downloads with your token attached.
5. **Findings for every tool** — each tool has a dedicated backend parser that
   turns its output into a severity-tagged findings table:

   | Tool | Parser extracts |
   |---|---|
   | Prowler | OCSF/ASFF findings (severity, status, resource ARN) |
   | ScoutSuite | severity summary lines |
   | Trivy | CVEs + misconfigs from its JSON report artifact |
   | kube-hunter / kube-bench | vulnerabilities / CIS pass-fail rows |
   | nmap | open ports with host:port, scan report hosts |
   | cloud_enum / CloudBrute / MicroBurst | open/protected cloud assets by URL |
   | CloudFox | ARNs, loot files, errors |
   | enumerate-iam | enumerated IAM actions |
   | GCP Scanner | project resource inventory from its JSON output |
   | anything else (`generic`) | errors, open ports, cloud URLs, ARNs, notes |

   Raw output is normalised first (ANSI colour codes stripped, `\r` progress
   bars unwrapped) — tools that colour their findings still parse correctly.
   Console output and report artifacts are merged, deduplicated by (id,
   resource), and the active parser/source is shown in the UI.
6. **Terminal** — full interactive shell in the toolbox container with every tool
   on PATH (this is how you drive interactive tools like Pacu's console).
7. **Add a tool** — Tool Manager → Add Tool. See the parameter types below.

### Parameter types

| Type | Renders as | Use for |
|---|---|---|
| `string` | the raw value | paths, image names, free text |
| `bool` | checkbox | on/off switches |
| `select` | dropdown | fixed choice lists |
| `flag` | `--name value`, **omitted when empty** | optional CLI switches |

A `flag` param with `flag: --region` and an empty value disappears from the command
entirely, which is what optional CLI switches need. `{job_id}` is always injected.

## Adding a tool via GUI (fields)

| Field | Meaning |
|---|---|
| Name | unique id, e.g. `my-scanner` |
| Display name | shown in UI |
| Docker image | any image (defaults to the toolbox image) |
| Command template | e.g. `prowler aws --profile {profile} {extra_args}` |
| Params | name, label, type (string/bool/select), default, required, help |
| Output type | `raw` / `prowler` / `scoutsuite` / `trivy` / `kube-hunter` |
| Category | aws / azure / gcp / kubernetes / general |

## Verify the stack

```bash
# containers healthy + API up (the UI sends the auth header for you; see src/api.js)
docker compose ps

# confirm every tool actually runs inside the toolbox image
docker cp toolbox/verify_tools.sh cptm-toolbox:/tmp/vt.sh
docker exec cptm-toolbox bash /tmp/vt.sh

# validate all seed specs parse (catches YAML mistakes before startup)
cd backend && python validate_seeds.py
```

`verify_tools.sh` probes each tool with an argument it supports (not just
`--version`) and reports OK / MISSING / BROKEN per tool.

## Tool status (verified in-image)

All 18 binary tools were probed inside the built image and start correctly:

| Tool | Category | Status |
|---|---|---|
| Prowler 5.44 | aws/azure/gcp | OK |
| ScoutSuite 5.14 | aws/azure/gcp | OK |
| Pacu 1.7 | aws | OK |
| CloudFox 1.17 | aws | OK |
| PMapper | aws | OK |
| enumerate-iam | aws | OK |
| ROADrecon | azure | OK |
| MicroBurst | azure | OK (PowerShell) |
| GCP Scanner | gcp | OK |
| cloud_enum | general | OK |
| CloudBrute | general | OK |
| kube-hunter | kubernetes | OK |
| kube-bench | kubernetes | OK |
| Trivy 0.75 | general | OK |
| kubectl / aws / az | misc | OK |
| Nmap 7.99 | general | OK |

## Troubleshooting / build notes

Things that bite when you rebuild this image, and how they are handled:

- **Kali ships Python 3.14.** Prowler and GCP Scanner break on it (old pydantic:
  `unable to infer type for attribute "Compliance"`). The Dockerfile installs a
  `uv`-managed **Python 3.12** and puts every version-sensitive tool in its own
  3.12 venv via `install_py.sh`. **PMapper** needs Python 3.9 plus a
  `sitecustomize.py` shim for the removed `collections.Mapping`.
- **Tool source locations drift.** `enumerate-iam` has no packaging metadata,
  `cloud_enum` is a Python package (not Go), and CloudBrute moved to
  `0xsha/CloudBrute`. The Dockerfile reflects the current upstream locations.
- **kube-bench release assets are versioned** (`kube-bench_<ver>_linux_amd64.tar.gz`),
  so the version is resolved from the GitHub API at build time.
- **Job containers inherit mounts** from the toolbox container (`volumes_from`)
  instead of hard-coded host paths, so credentials/workspace/artifacts line up
  regardless of where you clone the repo.
- **Findings come from artifacts too**, not only stdout: tools like Trivy write a
  pretty-printed JSON report to `/artifacts`, and the findings endpoint parses the
  richest artifact before falling back to console output.

## Safety defaults

- Backend binds `127.0.0.1` unless explicitly changed.
- API token required for all endpoints except `/api/health` (liveness only); the UI
  authenticates against `/api/auth/check` and shows a login screen on 401.
- Credential dir mounted **read-only**.
- Job containers are removed on completion to avoid leaking history.

## Verification (what has actually been tested)

```bash
python ui_flow_test.py      # auth gate, tool list, launch path
python live_test.py         # live WebSocket streaming + terminal PTY + findings
cd backend && python parser_tests.py      # 15 parser cases, all output shapes
cd backend && python audit_templates.py   # no template references a missing param
cd backend && python validate_seeds.py    # every seed YAML is well formed
```

Status at last run:

- **All 19 tools launch** through the API (`launch_all_test.py`).
- **Real cloud recon works**: `cloud_enum` and `CloudBrute` ran against public
  infrastructure and `cloud_enum` discovered live protected S3 buckets.
- **Real image scanning works**: `trivy` scanned public images and parsed CVEs
  (e.g. nginx:1.27-alpine → 161 findings, 2 critical) from its JSON artifact.
- **Live output, terminal PTY, findings, cancel** all verified end to end.
- Cloud posture tools (Prowler, ScoutSuite, PMapper, ROADrecon, GCP Scanner,
  enumerate-iam, kube-bench) fail with **correct credential/permission errors**
  when no cloud credentials are mounted — which is the expected behaviour.

Not tested: a full end-to-end run against a live cloud account (this host has no
cloud credentials). Mount real credentials into `credentials/` and those same tools
will run against your authorised environment.

## License / responsible use

This project orchestrates existing open-source tools for **authorized** penetration testing
only. Respect each tool's license and your engagement's rules of engagement.
