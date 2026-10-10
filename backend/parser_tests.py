"""Unit tests for every tool parser with realistic output samples."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cptm.parsers import parse_output

CASES = []


def case(name, output_type, text, expect_min, expect_contains=None):
    CASES.append((name, output_type, text, expect_min, expect_contains))


# ---- nmap ----
case(
    "nmap open ports + host",
    "nmap",
    """Starting Nmap 7.99 ( https://nmap.org )
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.30s latency).
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
443/tcp closed https
Nmap done: 1 IP address (1 host up) scanned in 4.00 seconds""",
    2,
    ["22/tcp", "scanme.nmap.org:22"],
)

# ---- cloud_enum ----
case(
    "cloud_enum open bucket + protected firebase",
    "cloud-enum",
    """[+] Checking for S3 buckets
  Open S3 Bucket: http://flaws-cloud.s3.amazonaws.com/
[+] Checking for Google Firebase Realtime Databases
  Protected Google Firebase RTDB: https://mobile-flaws.firebaseio.com/.json
[+] All done, happy hacking!""",
    2,
    ["flaws-cloud.s3.amazonaws.com", "mobile-flaws.firebaseio.com"],
)

# ---- cloudbrute (real output: bare URL lines when a bucket is hit) ----
case(
    "cloudbrute found line",
    "cloudbrute",
    """5:31PM INF Initialized scan config
5:31PM INF amazon detected
https://flaws2-storage.s3.amazonaws.com/
5:31PM INF Scan complete""",
    1,
    ["flaws2-storage"],
)

# ---- trivy (pretty JSON document) ----
case(
    "trivy vulns",
    "trivy",
    """{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "alpine:3.19 (alpine 3.19.9)",
      "Type": "alpine",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.1.4", "Severity": "HIGH", "Title": "bo"}
      ]
    }
  ]
}""",
    1,
    ["CVE-2024-0001"],
)

# ---- prowler OCSF ----
case(
    "prowler OCSF finding",
    "prowler",
    """{
  "finding_info": {"uid": "iam_mfa_root", "title": "Root MFA not enabled", "desc": "iam"},
  "severity": "high",
  "severity_id": 4,
  "status": "FAIL",
  "cloud": {"service_name": "iam"},
  "resources": [{"uid": "arn:aws:iam::123456789012:root", "name": "root"}]
}""",
    1,
    ["iam_mfa_root", "arn:aws:iam::123456789012:root"],
)

# ---- prowler legacy ASFF line ----
case(
    "prowler legacy line",
    "prowler",
    '{"CheckID": "s3_public", "Severity": "critical", "Status": "FAIL", "ServiceName": "s3", "CheckTitle": "Public bucket", "ResourceDetails": "arn:aws:s3:::x"}',
    1,
    ["s3_public"],
)

# ---- scoutsuite ----
case(
    "scoutsuite summary",
    "scoutsuite",
    """Scout Suite completed
high: 3 findings related to IAM
medium: 12 findings related to S3""",
    2,
    ["IAM", "S3"],
)

# ---- kube-bench ----
case(
    "kube-bench pass/fail",
    "kube-bench",
    """[PASS] 1.2.1 Ensure anonymous-auth is false
[FAIL] 1.2.2 Ensure basic-auth is not set""",
    2,
    ["1.2.1", "1.2.2"],
)

# ---- kube-hunter ----
case(
    "kube-hunter json",
    "kube-hunter",
    """Starting hunter...
{"vulnerabilities": [{"vulnerability_id": "KHV050", "severity": "high", "category": "Access Control", "vulnerability": "Anonymous auth", "location": "10.0.0.1:6443"}]}""",
    1,
    ["KHV050"],
)

# ---- cloudfox ----
case(
    "cloudfox arn + loot",
    "cloudfox",
    """[🦊] Enumerating IAM principals
arn:aws:iam::123456789012:role/admin
Loot File: [/workspace/loot/cloudfox/iam-principals.txt]
CRITICAL: profile missing""",
    2,
    ["arn:aws:iam::123456789012:role/admin"],
)

# ---- enumerate-iam ----
case(
    "enumerate-iam allowed actions",
    "enumerate-iam",
    """iam:GetUser - enumerated
129 iam:ListAccessKeys attempted
s3:ListBucket allowed for this principal""",
    1,
    ["iam:GetUser"],
)

# ---- gcp-scanner ----
case(
    "gcp-scanner json",
    "gcp-scanner",
    """{"Compute Engines": {"vm-1": {"status": "RUNNING"}}, "Storage Buckets": ["bucket-a", "bucket-b"]}""",
    2,
    ["Compute Engines"],
)

# ---- microburst ----
case(
    "microburst found storage",
    "microburst",
    """Testing base: flaws
[+] Found storage account: https://flaws.blob.core.windows.net/""",
    1,
    ["flaws.blob.core.windows.net"],
)

# ---- generic fallback (unknown tool type) ----
case(
    "generic fallback with mixed content",
    "generic",
    """[+] Starting scan
Open https://example.s3.amazonaws.com/
ERROR: something went wrong
arn:aws:s3:::some-bucket""",
    3,
    None,
)

# ---- raw legacy type still works ----
case(
    "raw falls back to generic",
    "raw",
    "ERROR: legacy job\n[+] note line",
    1,
    None,
)


passed, failed = 0, 0
for name, otype, text, expect_min, contains in CASES:
    result = parse_output(otype, text)
    n = len(result["findings"])
    ok = n >= expect_min
    detail = ""
    if ok and contains:
        blob = " ".join(
            f"{f['id']} {f['title']} {f['resource']}" for f in result["findings"]
        )
        missing = [c for c in contains if c not in blob]
        ok = not missing
        detail = f"missing={missing}" if missing else ""
    if not ok:
        detail = detail or f"got {n} findings, expected >= {expect_min}"
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name} (parser={result['parser']}, findings={n}) {detail}")
    passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

print(f"\n{passed}/{passed + failed} parser cases pass")
sys.exit(1 if failed else 0)
