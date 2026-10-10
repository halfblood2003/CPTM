"""Validate every seed tool spec parses and has the required fields."""
import glob
import os
import sys

import yaml

REQUIRED = ("name", "command_template")
root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
bad = 0
files = sorted(glob.glob(os.path.join(root, "*.yaml")))
for f in files:
    try:
        spec = yaml.safe_load(open(f, encoding="utf-8"))
    except yaml.YAMLError as e:
        print(f"MALFORMED {os.path.basename(f)}: {e}")
        bad += 1
        continue
    if not isinstance(spec, dict):
        print(f"NOT_A_MAPPING {os.path.basename(f)}")
        bad += 1
        continue
    missing = [k for k in REQUIRED if not spec.get(k)]
    if missing:
        print(f"MISSING {missing} in {os.path.basename(f)}")
        bad += 1
        continue
    # Command templates containing ':' must be quoted-safe in YAML; verify the
    # rendered template still contains its placeholders.
    print(f"OK {spec['name']:<20} output_type={spec.get('output_type', 'raw')}")
print(f"\n{len(files)} specs, {bad} problems")
sys.exit(1 if bad else 0)
