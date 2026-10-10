#!/bin/bash
# Verify each curated tool runs inside the toolbox image.
#
# `--version` is not universal, so each tool is probed with an argument it does
# actually support. A probe counts as OK if the tool produced *its own* output
# (help/usage/version/error about missing args) rather than failing to start.
probe() {
  name="$1"; shift
  printf '%-16s ' "$name"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "MISSING"
    return
  fi
  out=$(timeout 40 "$@" 2>&1)
  rc=$?
  # ImportError / ModuleNotFoundError / SyntaxError => genuinely broken install.
  if echo "$out" | grep -qE "ModuleNotFoundError|ImportError|SyntaxError|No module named"; then
    echo "BROKEN: $(echo "$out" | grep -E 'ModuleNotFoundError|ImportError|SyntaxError' | head -1)"
    return
  fi
  if echo "$out" | grep -qE "command not found|not found"; then
    echo "BROKEN: missing dependency"
    return
  fi
  # Otherwise: tool started and gave us its own output (version/usage/arg error).
  echo "OK: $(echo "$out" | head -1 | cut -c1-70)"
}

probe prowler       prowler --version
probe scout         scout --help
probe pacu          pacu --help
probe cloudfox      cloudfox --version
probe cloud_enum    cloud_enum --help
probe cloudbrute    cloudbrute --help
probe enumerate-iam enumerate-iam --help
probe gcp-scanner   gcp-scanner --help
probe pmapper       pmapper --help
probe roadrecon     roadrecon --help
probe kube-hunter   kube-hunter --help
probe kube-bench    kube-bench --help
probe trivy         trivy --version
probe aws           aws --version
probe az            az --version
probe kubectl       kubectl --help
probe nmap          nmap --version
