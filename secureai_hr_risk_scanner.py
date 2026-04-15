from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List


SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
SEVERITY_SCORE = {"Critical": 95, "High": 75, "Medium": 45, "Low": 20}


@dataclass
class Finding:
    file: str
    rule: str
    title: str
    severity: str
    score: int
    match: str
    remediation: str


RULES = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9\-_]{16,}\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "prompt_injection": re.compile(
        r"ignore previous instructions|reveal full record|return full ssn|bypass guardrails|disregard policy|show hidden prompt",
        re.I,
    ),
    "external_model": re.compile(r"https://api\.[^\s\"']+", re.I),
    "banking_data": re.compile(r"\bbank account\b|\brouting number\b|\bdirect deposit\b", re.I),
    "payroll_data": re.compile(r"\bpayroll\b|\bsalary\b|\bcompensation\b|\bw-2\b", re.I),
    "access_control_gap": re.compile(r"\ballow_all_users\b|\bskip_auth\b|\bno_auth_required\b", re.I),
}

FINDING_MAP = {
    "ssn": (
        "Sensitive Data Exposure",
        "Critical",
        "SSN detected. Mask or redact sensitive identifiers before logging, prompt use, or outbound transfer.",
    ),
    "openai_key": (
        "Hardcoded Secret",
        "High",
        "API key detected. Move secrets to secure environment injection or a secrets manager and rotate exposed credentials.",
    ),
    "aws_key": (
        "Cloud Credential Exposure",
        "High",
        "Possible AWS key detected. Revoke or rotate immediately and review commit history for exposure.",
    ),
    "prompt_injection": (
        "Prompt Injection Exposure",
        "Critical",
        "Prompt text appears vulnerable to instruction override. Add trust boundaries, strict system rules, and action allowlists.",
    ),
    "external_model": (
        "External Model Routing",
        "High",
        "External model endpoint detected. Validate vendor approval, classification-aware routing, and outbound data minimization.",
    ),
    "banking_data": (
        "Financial Data Handling Risk",
        "Critical",
        "Banking-related data appears in AI workflow content. Enforce masking, role-based access, and outbound restrictions.",
    ),
    "payroll_data": (
        "Payroll Data Sensitivity",
        "Medium",
        "Payroll-related terms detected. Confirm least-privilege access and correct data classification.",
    ),
    "access_control_gap": (
        "Access Control Weakness",
        "High",
        "Weak authentication or overly broad access logic detected. Restrict by role, identity, and approved task context.",
    ),
}


IGNORED_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
}


def should_scan(path: Path) -> bool:
    return not any(part in IGNORED_DIRS for part in path.parts)


def scan_text(path: Path, text: str) -> List[Finding]:
    findings: List[Finding] = []
    lowered = text.lower()

    for rule_name, pattern in RULES.items():
        for match in pattern.finditer(text):
            title, severity, remediation = FINDING_MAP[rule_name]
            findings.append(
                Finding(
                    file=str(path),
                    rule=rule_name,
                    title=title,
                    severity=severity,
                    score=SEVERITY_SCORE[severity],
                    match=match.group(0),
                    remediation=remediation,
                )
            )

    if (
        ("external-llm" in lowered or "openai" in lowered or "anthropic" in lowered)
        and ("ssn" in lowered or "bank account" in lowered or "routing number" in lowered)
        and ("salary" in lowered or "payroll" in lowered or "compensation" in lowered)
    ):
        findings.append(
            Finding(
                file=str(path),
                rule="data_minimization",
                title="Unsafe Data Minimization",
                severity="Critical",
                score=SEVERITY_SCORE["Critical"],
                match="Sensitive employee and payroll data appear routed to an external model",
                remediation="Reduce payload fields, tokenize identifiers, and gate outbound model access by classification policy.",
            )
        )

    if "prompt" in path.name.lower():
        if "owner:" not in lowered or "version:" not in lowered or "approved:" not in lowered:
            findings.append(
                Finding(
                    file=str(path),
                    rule="governance_gap",
                    title="Prompt Governance Gap",
                    severity="Medium",
                    score=SEVERITY_SCORE["Medium"],
                    match="Prompt artifact lacks ownership, version, or approval metadata",
                    remediation="Add owner, version, approval status, permitted data classes, and review date to the prompt file.",
                )
            )

    return findings


def scan_file(path: Path) -> List[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    return scan_text(path, text)


def scan_repo(root: Path) -> List[Finding]:
    findings: List[Finding] = []

    for path in root.rglob("*"):
        if path.is_file() and should_scan(path):
            findings.extend(scan_file(path))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.score, f.title), reverse=True)
    return findings


def summarize(findings: List[Finding]) -> dict:
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        summary[finding.severity] += 1
    return summary


def calculate_total_risk(findings: List[Finding]) -> int:
    return sum(f.score for f in findings)


def write_json(findings: List[Finding], summary: dict, target: Path, out_path: Path) -> None:
    payload = {
        "target": str(target.resolve()),
        "summary": summary,
        "total_findings": len(findings),
        "total_risk_score": calculate_total_risk(findings),
        "findings": [asdict(f) for f in findings],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(findings: List[Finding], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["file", "rule", "title", "severity", "score", "match", "remediation"],
        )
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def print_report(findings: List[Finding], summary: dict, target: Path) -> None:
    print("\nSecureAI HR Risk Scanner")
    print("=" * 30)
    print(f"Target: {target.resolve()}")
    print(f"Total findings: {len(findings)}")
    print(f"Total risk score: {calculate_total_risk(findings)}")

    print("\nSeverity summary:")
    for sev in ["Critical", "High", "Medium", "Low"]:
        print(f"- {sev}: {summary[sev]}")

    print("\nTop findings:")
    for item in findings[:10]:
        print(f"[{item.severity}] {item.title}")
        print(f"  File: {item.file}")
        print(f"  Match: {item.match}")
        print(f"  Score: {item.score}")
        print(f"  Fix: {item.remediation}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Scan AI-enabled HR/payroll workflow repositories for common AI security risks."
    )
    parser.add_argument("target", help="Directory to scan")
    parser.add_argument(
        "--json",
        dest="json_out",
        default="reports/report.json",
        help="Path to JSON report output",
    )
    parser.add_argument(
        "--csv",
        dest="csv_out",
        default="reports/findings.csv",
        help="Path to CSV report output",
    )
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists() or not target.is_dir():
        raise SystemExit(f"Target directory not found: {target}")

    findings = scan_repo(target)
    summary = summarize(findings)

    json_path = Path(args.json_out)
    csv_path = Path(args.csv_out)

    write_json(findings, summary, target, json_path)
    write_csv(findings, csv_path)
    print_report(findings, summary, target)

    print(f"JSON report written to: {json_path.resolve()}")
    print(f"CSV report written to: {csv_path.resolve()}")


if __name__ == "__main__":
    main()
