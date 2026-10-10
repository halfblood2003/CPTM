"""Output parsers: turn tool output into structured findings.

Every tool in the registry maps to a parser via its `output_type`:

  prowler       Prowler OCSF / JSON-ASFF documents and JSON lines
  scoutsuite    ScoutSuite console summary
  trivy         Trivy JSON reports
  kube-hunter   kube-hunter JSON report / table output
  kube-bench    kube-bench [PASS]/[FAIL] lines
  nmap          nmap scan reports and port tables
  cloud-enum    cloud_enum Open/Protected asset lines
  cloudbrute    CloudBrute found-bucket lines
  cloudfox      CloudFox ARNs, loot files, errors
  enumerate-iam enumerate-iam allowed-action lines
  gcp-scanner   GCP Scanner JSON result files
  microburst    MicroBurst found-storage lines
  generic       shared fallback: errors, open ports, cloud assets, ARNs

Unknown output types fall back to `generic`, so every tool yields a useful
Findings tab rather than "no structured findings".
"""
from __future__ import annotations

import json
import re


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------

def _count_by(items: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for it in items:
        v = str(it.get(key, "unknown"))
        out[v] = out.get(v, 0) + 1
    return out


def _cap(findings: list[dict], limit: int = 2000) -> list[dict]:
    return findings[:limit]


def _extract_json_objects(text: str):
    """Yield JSON objects from mixed tool output.

    Handles both shapes tools actually emit:
      * a whole pretty-printed JSON document (trivy --format json > file)
      * newline-delimited JSON objects (prowler OCSF/JSON-ASFF lines)
    """
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            doc = json.loads(stripped)
            if isinstance(doc, dict):
                yield doc
            elif isinstance(doc, list):
                for item in doc:
                    if isinstance(item, dict):
                        yield item
            return
        except json.JSONDecodeError:
            pass  # fall through to line-by-line

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
            except json.JSONDecodeError:
                continue


_NMAP_PORT = re.compile(
    r"^(\d+/(?:tcp|udp))\s+(open|closed|filtered)\s+(\S+)[ \t]*(.*)$", re.M
)
_NMAP_REPORT = re.compile(r"Nmap scan report for (\S+)\s*(?:\(([\d.]+)\))?")
_CLOUD_ASSET = re.compile(
    r"^\s*(Open|Protected|Potential)\s+(.+?):\s*(\S+)\s*$", re.M
)
_FOUND_URL = re.compile(
    r"https?://\S+"
    r"|\b[\w.-]+\.(?:s3\.amazonaws\.com|blob\.core\.windows\.net|firebaseio\.com"
    r"|storage\.googleapis\.com|cloudfront\.net|azurewebsites\.net)\b",
    re.I,
)
_FOUND_LINE = re.compile(r"(?i)\b(found|open|valid|exists)\b")
_ARN = re.compile(r"arn:(?:aws|aws-cn|aws-us-gov|azure|gcp):\S+")
_ERROR_LINE = re.compile(
    r"^\s*(?:CRITICAL|ERROR|FATAL)\b|Traceback \(most recent call last\)", re.M
)
_ACTION = re.compile(
    r"\b(?:iam|s3|ec2|sts|sns|sqs|lambda|dynamodb|kms|cloudtrail|ec2metadata"
    r"|cloudwatch|logs|secretsmanager|ssm):[A-Za-z0-9]+"
)
_INFO_LINE = re.compile(r"^\s*\[\+\]\s+(.*)$")


# --------------------------------------------------------------------------
# structured-output parsers
# --------------------------------------------------------------------------

def _parse_prowler(text: str) -> dict:
    """Prowler 5 OCSF documents, JSON-ASFF lines, and legacy flat JSON lines."""
    findings = []
    for obj in _extract_json_objects(text):
        fi = obj.get("finding_info") if isinstance(obj.get("finding_info"), dict) else None
        if fi is not None or "severity_id" in obj:
            resources = obj.get("resources") or []
            resource = ""
            if isinstance(resources, list) and resources:
                first = resources[0] if isinstance(resources[0], dict) else {}
                resource = first.get("uid") or first.get("name") or ""
            cloud = obj.get("cloud") if isinstance(obj.get("cloud"), dict) else {}
            findings.append(
                {
                    "id": (fi or {}).get("uid") or obj.get("uid", ""),
                    "severity": str(obj.get("severity") or "unknown").lower(),
                    "status": obj.get("status") or obj.get("status_code", ""),
                    "service": cloud.get("service_name") or (fi or {}).get("desc", ""),
                    "title": (fi or {}).get("title") or obj.get("message", ""),
                    "resource": resource,
                }
            )
            continue

        if isinstance(obj.get("Finding"), (str, int)) or "CheckID" in obj:
            findings.append(
                {
                    "id": obj.get("CheckID") or obj.get("Finding"),
                    "severity": obj.get("Severity", "unknown"),
                    "status": obj.get("Status", ""),
                    "service": obj.get("ServiceName", ""),
                    "title": obj.get("CheckTitle", obj.get("Finding", "")),
                    "resource": obj.get("ResourceDetails", obj.get("ResourceArn", "")),
                }
            )
    return {
        "parser": "prowler",
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by(findings, "severity"),
            "by_status": _count_by(findings, "status"),
        },
        "findings": _cap(findings),
    }


def _parse_scoutsuite(text: str) -> dict:
    findings = []
    pattern = re.compile(
        r"(?P<sev>critical|high|medium|low|warning)\s*[:\-]?\s*(?P<items>.+)",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        m = pattern.search(line)
        if m:
            findings.append(
                {
                    "id": "",
                    "severity": m.group("sev").lower(),
                    "status": "",
                    "service": "",
                    "title": m.group("items").strip()[:200],
                    "resource": "",
                }
            )
    return {
        "parser": "scoutsuite",
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


def _parse_trivy(text: str) -> dict:
    findings = []
    for obj in _extract_json_objects(text):
        results = obj.get("Results") or []
        for res in results:
            target = res.get("Target", "")
            for v in res.get("Vulnerabilities") or []:
                findings.append(
                    {
                        "id": v.get("VulnerabilityID", ""),
                        "severity": v.get("Severity", "unknown"),
                        "status": v.get("Status", ""),
                        "service": res.get("Type", target),
                        "title": v.get("Title") or v.get("PkgName", ""),
                        "resource": f"{v.get('PkgName', '')}@{v.get('InstalledVersion', '')}",
                    }
                )
            for m in res.get("Misconfigurations") or []:
                findings.append(
                    {
                        "id": m.get("ID", ""),
                        "severity": m.get("Severity", "unknown"),
                        "status": m.get("Status", ""),
                        "service": res.get("Type", target),
                        "title": m.get("Title", ""),
                        "resource": target,
                    }
                )
    return {
        "parser": "trivy",
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


def _parse_kube_hunter(text: str) -> dict:
    findings = []
    try:
        start = text.index("{")
        obj = json.loads(text[start:])
        for vuln in obj.get("vulnerabilities", []):
            findings.append(
                {
                    "id": vuln.get("vulnerability_id", ""),
                    "severity": vuln.get("severity", "unknown").lower(),
                    "status": "",
                    "service": vuln.get("category", ""),
                    "title": vuln.get("vulnerability", ""),
                    "resource": vuln.get("location", ""),
                }
            )
    except (ValueError, json.JSONDecodeError):
        pass
    if not findings:
        for line in text.splitlines():
            if "|" in line and ("High" in line or "Medium" in line or "Low" in line):
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 2:
                    sev = next(
                        (p.lower() for p in parts if p.lower() in ("high", "medium", "low")),
                        "unknown",
                    )
                    findings.append(
                        {
                            "id": "",
                            "severity": sev,
                            "status": "",
                            "service": "",
                            "title": parts[0][:200],
                            "resource": parts[1][:200] if len(parts) > 1 else "",
                        }
                    )
    return {
        "parser": "kube-hunter",
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


def _parse_kube_bench(text: str) -> dict:
    findings = []
    for line in text.splitlines():
        m = re.match(r"\[(\w+)\]\s+([\d.]+)\s+(?P<txt>.+)", line)
        if m:
            sev = "fail" if m.group(1).lower() == "fail" or "fail" in line.lower() else "pass"
            findings.append(
                {
                    "id": m.group(2),
                    "severity": sev,
                    "status": sev,
                    "service": "",
                    "title": m.group("txt").strip()[:200],
                    "resource": "",
                }
            )
    return {
        "parser": "kube-bench",
        "summary": {
            "total_findings": len(findings),
            "by_status": _count_by(findings, "status"),
        },
        "findings": _cap(findings),
    }


# --------------------------------------------------------------------------
# raw-output parsers (one per tool)
# --------------------------------------------------------------------------

def _parse_nmap(text: str) -> dict:
    findings = []
    hosts = set()
    for m in _NMAP_REPORT.finditer(text):
        hosts.add(m.group(1))
    for m in _NMAP_PORT.finditer(text):
        port, state, service, extra = m.groups()
        if state != "open":
            continue
        findings.append(
            {
                "id": port,
                "severity": "open",
                "status": "open",
                "service": "nmap",
                "title": f"{service} {extra}".strip(),
                "resource": f"{next(iter(hosts), '')}:{port}",
            }
        )
    return {
        "parser": "nmap",
        "summary": {
            "total_findings": len(findings),
            "hosts_up": len(hosts),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


def _parse_cloud_enum(text: str) -> dict:
    findings = []
    for m in _CLOUD_ASSET.finditer(text):
        state, service, url = m.groups()
        sev = {"open": "high", "protected": "info", "potential": "medium"}.get(
            state.lower(), "info"
        )
        findings.append(
            {
                "id": "cloud-asset",
                "severity": sev,
                "status": state.lower(),
                "service": service.strip()[:60],
                "title": f"{state} {service.strip()}: {url}",
                "resource": url,
            }
        )
    # Also surface the plain "Open <url>" variant cloud_enum emits for some checks.
    for line in text.splitlines():
        if line.strip().startswith("Open ") and _FOUND_URL.search(line):
            url = _FOUND_URL.search(line).group(0)
            if not any(f["resource"] == url for f in findings):
                findings.append(
                    {
                        "id": "cloud-asset",
                        "severity": "high",
                        "status": "open",
                        "service": "cloud_enum",
                        "title": line.strip()[:180],
                        "resource": url,
                    }
                )
    return {
        "parser": "cloud-enum",
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


def _parse_cloudbrute(text: str) -> dict:
    findings = []
    for line in text.splitlines():
        stripped = line.strip()
        # CloudBrute prints a bare URL on its own line when it hits a bucket;
        # other lines are INF/progress noise.
        m = _FOUND_URL.search(stripped)
        if m and (stripped == m.group(0) or _FOUND_LINE.search(stripped)):
            findings.append(
                {
                    "id": "found-asset",
                    "severity": "high",
                    "status": "found",
                    "service": "cloudbrute",
                    "title": stripped[:180],
                    "resource": m.group(0),
                }
            )
    findings.extend(_error_findings(text))
    return {
        "parser": "cloudbrute",
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


def _parse_cloudfox(text: str) -> dict:
    findings = []
    seen_arns = set()
    for line in text.splitlines():
        for m in _ARN.finditer(line):
            arn = m.group(0).rstrip(".,;)]}")
            if arn not in seen_arns:
                seen_arns.add(arn)
                findings.append(
                    {
                        "id": "aws-resource",
                        "severity": "info",
                        "status": "",
                        "service": "cloudfox",
                        "title": line.strip()[:180] or arn,
                        "resource": arn,
                    }
                )
        lm = re.search(r"(?i)loot file\S*[:\s]+\[?(/\S+?)\]?\s*$", line)
        if lm:
            findings.append(
                {
                    "id": "loot-file",
                    "severity": "info",
                    "status": "",
                    "service": "cloudfox",
                    "title": line.strip()[:180],
                    "resource": lm.group(1),
                }
            )
    findings.extend(_error_findings(text))
    return {
        "parser": "cloudfox",
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


def _parse_enumerate_iam(text: str) -> dict:
    findings = []
    seen = set()
    for line in text.splitlines():
        for m in _ACTION.finditer(line):
            action = m.group(0)
            if action not in seen:
                seen.add(action)
                findings.append(
                    {
                        "id": action,
                        "severity": "info",
                        "status": "allowed",
                        "service": "enumerate-iam",
                        "title": f"Action enumerated: {action}",
                        "resource": "",
                    }
                )
    findings.extend(_error_findings(text))
    return {
        "parser": "enumerate-iam",
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


def _parse_gcp_scanner(text: str) -> dict:
    findings = []
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            doc = json.loads(stripped)
            items = doc.items() if isinstance(doc, dict) else enumerate(doc)
            for key, val in items:
                if isinstance(val, dict):
                    detail = f"{len(val)} keys: {', '.join(list(val)[:5])}"
                elif isinstance(val, list):
                    detail = f"{len(val)} items"
                else:
                    detail = str(val)[:120]
                findings.append(
                    {
                        "id": str(key)[:80],
                        "severity": "info",
                        "status": "",
                        "service": "gcp-scanner",
                        "title": f"{key}: {detail}"[:180],
                        "resource": "",
                    }
                )
        except json.JSONDecodeError:
            pass
    if not findings:
        findings.extend(_generic_findings(text))
    return {
        "parser": "gcp-scanner",
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


def _parse_microburst(text: str) -> dict:
    findings = []
    for line in text.splitlines():
        if _FOUND_LINE.search(line):
            m = _FOUND_URL.search(line)
            if m:
                findings.append(
                    {
                        "id": "found-storage",
                        "severity": "high",
                        "status": "found",
                        "service": "microburst",
                        "title": line.strip()[:180],
                        "resource": m.group(0),
                    }
                )
    findings.extend(_error_findings(text))
    return {
        "parser": "microburst",
        "summary": {
            "total_findings": len(findings),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


# --------------------------------------------------------------------------
# generic fallback
# --------------------------------------------------------------------------

def _error_findings(text: str) -> list[dict]:
    out = []
    for m in _ERROR_LINE.finditer(text):
        line = text[m.start(): text.find("\n", m.start()) or None].strip()
        out.append(
            {
                "id": "error",
                "severity": "high",
                "status": "",
                "service": "stderr",
                "title": line[:180],
                "resource": "",
            }
        )
    return out


def _generic_findings(text: str) -> list[dict]:
    findings = []
    findings.extend(_error_findings(text))

    for m in _NMAP_PORT.finditer(text):
        port, state, service, extra = m.groups()
        if state == "open":
            findings.append(
                {
                    "id": port,
                    "severity": "open",
                    "status": "open",
                    "service": "portscan",
                    "title": f"{service} {extra}".strip(),
                    "resource": port,
                }
            )

    for line in text.splitlines():
        if _FOUND_LINE.search(line):
            m = _FOUND_URL.search(line)
            if m:
                findings.append(
                    {
                        "id": "cloud-asset",
                        "severity": "medium",
                        "status": "found",
                        "service": "recon",
                        "title": line.strip()[:180],
                        "resource": m.group(0),
                    }
                )

    seen_arns = set()
    for line in text.splitlines():
        for m in _ARN.finditer(line):
            arn = m.group(0).rstrip(".,;)]}")
            if arn not in seen_arns:
                seen_arns.add(arn)
                findings.append(
                    {
                        "id": "resource",
                        "severity": "info",
                        "status": "",
                        "service": "",
                        "title": line.strip()[:180] or arn,
                        "resource": arn,
                    }
                )

    count = 0
    for m in _INFO_LINE.finditer(text):
        findings.append(
            {
                "id": "note",
                "severity": "info",
                "status": "",
                "service": "",
                "title": m.group(1).strip()[:180],
                "resource": "",
            }
        )
        count += 1
        if count >= 50:
            break
    return findings


def _parse_generic(text: str) -> dict:
    findings = _generic_findings(text)
    return {
        "parser": "generic",
        "summary": {
            "total_findings": len(findings),
            "lines": len(text.splitlines()),
            "by_severity": _count_by(findings, "severity"),
        },
        "findings": _cap(findings),
    }


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------

PARSERS = {
    "prowler": _parse_prowler,
    "scoutsuite": _parse_scoutsuite,
    "trivy": _parse_trivy,
    "kube-hunter": _parse_kube_hunter,
    "kube-bench": _parse_kube_bench,
    "nmap": _parse_nmap,
    "cloud-enum": _parse_cloud_enum,
    "cloudbrute": _parse_cloudbrute,
    "cloudfox": _parse_cloudfox,
    "enumerate-iam": _parse_enumerate_iam,
    "gcp-scanner": _parse_gcp_scanner,
    "microburst": _parse_microburst,
}


ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[a-zA-Z]"          # CSI sequences (colours, cursor)
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences (titles, hyperlinks)
    r"|\x9b[0-9;?]*[a-zA-Z]"           # single-byte CSI variant
)


def parse_output(output_type: str, text: str) -> dict:
    """Return {'summary': ..., 'findings': [...], 'parser': name}.

    Unknown or 'raw' output types fall back to the generic extractor so every
    tool produces a useful Findings view.
    """
    fn = PARSERS.get(output_type)
    if fn is None:
        fn = _parse_generic
    # Tools colour their output (ANSI escapes) and emit \r progress bars;
    # normalise both or line-based regexes never match the real findings.
    text = ANSI_RE.sub("", text or "")
    text = text.replace("\r", "\n")
    try:
        return fn(text)
    except Exception:
        return {
            "parser": output_type or "raw",
            "summary": {"lines": len((text or "").splitlines())},
            "findings": [],
        }
