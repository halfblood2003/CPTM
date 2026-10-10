"""Audit tool specs for placeholders that have no matching parameter.

A template referencing {foo} with no `foo` param makes the tool impossible to
launch from the GUI (the launch endpoint rejects it as a missing required
parameter). This finds every such case before a user hits it.
"""
import glob
import os
import re
import string
import sys

import yaml

AUTO = {"job_id"}  # injected by the backend at launch time
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")

bad = 0
checked = 0
for f in sorted(glob.glob(os.path.join(root, "*.yaml"))):
    spec = yaml.safe_load(open(f, encoding="utf-8"))
    name = spec.get("name", os.path.basename(f))
    template = spec.get("command_template", "")
    declared = {p["name"] for p in (spec.get("params") or [])}

    # Find {placeholder} occurrences (str.format style used by the backend).
    used = set(re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", template))
    undefined = used - declared - AUTO
    # Params that exist but are never used are just dead UI fields.
    unused = declared - used

    checked += 1
    problems = []
    if undefined:
        problems.append(f"UNDEFINED PLACEHOLDERS {sorted(undefined)}")
        bad += 1
    if unused:
        problems.append(f"unused params {sorted(unused)}")

    if problems:
        print(f"{name:<22} {'; '.join(problems)}")
        if undefined:
            print(f"{'':<22}   template: {template}")
    else:
        print(f"{name:<22} OK")

print(f"\n{checked} specs checked, {bad} with undefined placeholders")
sys.exit(1 if bad else 0)
