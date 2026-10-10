# Dev & Verification Scripts

Test harnesses used to develop and verify CPTM. They are kept out of the app
itself — nothing here is required to run the platform.

## From the repo root

```bash
# Backend + frontend contract (auth gate, tool list, launch path) — needs the stack running
python docs/scripts/ui_flow_test.py

# Live WebSocket streaming, terminal PTY, findings, cancel
python docs/scripts/live_test.py

# Launch every registered tool through the API and classify the outcome
python docs/scripts/launch_all_test.py
python docs/scripts/classify_test.py

# Full suite: backend contract + frontend contract + all tools + output/artifacts/DB
python docs/scripts/master_test.py
```

## From `backend/` (no stack needed)

```bash
cd backend
python ../docs/scripts/parser_tests.py      # 15 parser cases, all output shapes
python ../docs/scripts/audit_templates.py   # no command template references a missing param
python ../docs/scripts/validate_seeds.py    # every seed YAML is well formed
```

`test_inputs.py` provides per-tool launch parameters for the harnesses.
`show_failure.py <tool>` prints the banner-stripped failure reason of a tool's
most recent job.

All scripts read the access token from the repo-root `.env` at runtime and
never print it.
