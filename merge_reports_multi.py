#!/usr/bin/env python3

import json
import os
import argparse
from collections import defaultdict
from typing import Dict, List, Any, Set
from datetime import datetime


# CWE Impact Factor Database (Expanded)
CWE_IMPACT_DB = {
    # Injection Flaws
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "base_impact": 7.5,
        "exploitability": "High",
    },
    "CWE-89": {
        "name": "SQL Injection",
        "base_impact": 9.5,
        "exploitability": "Critical",
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "base_impact": 9.5,
        "exploitability": "Critical",
    },
    "CWE-94": {
        "name": "Code Injection",
        "base_impact": 9.5,
        "exploitability": "Critical",
    },
    "CWE-74": {
        "name": "Injection (Generic)",
        "base_impact": 9.0,
        "exploitability": "Critical",
    },
    "CWE-77": {
        "name": "Command Injection",
        "base_impact": 9.5,
        "exploitability": "Critical",
    },
    "CWE-91": {"name": "XML Injection", "base_impact": 8.0, "exploitability": "High"},
    "CWE-611": {
        "name": "XML External Entity (XXE)",
        "base_impact": 8.5,
        "exploitability": "High",
    },
    # Memory Corruption
    "CWE-787": {
        "name": "Out-of-bounds Write",
        "base_impact": 9.0,
        "exploitability": "High",
    },
    "CWE-125": {
        "name": "Out-of-bounds Read",
        "base_impact": 7.5,
        "exploitability": "Medium",
    },
    "CWE-119": {
        "name": "Improper Restriction of Operations within Memory Buffer",
        "base_impact": 8.5,
        "exploitability": "High",
    },
    "CWE-120": {
        "name": "Buffer Copy without Checking Size of Input",
        "base_impact": 9.0,
        "exploitability": "High",
    },
    "CWE-122": {
        "name": "Heap-based Buffer Overflow",
        "base_impact": 9.0,
        "exploitability": "High",
    },
    "CWE-416": {"name": "Use After Free", "base_impact": 9.0, "exploitability": "High"},
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "base_impact": 6.5,
        "exploitability": "Medium",
    },
    "CWE-415": {"name": "Double Free", "base_impact": 8.5, "exploitability": "High"},
    "CWE-190": {
        "name": "Integer Overflow or Wraparound",
        "base_impact": 8.0,
        "exploitability": "Medium",
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "base_impact": 7.5,
        "exploitability": "High",
    },
    # Authentication & Authorization
    "CWE-287": {
        "name": "Improper Authentication",
        "base_impact": 8.5,
        "exploitability": "High",
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "base_impact": 8.5,
        "exploitability": "High",
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "base_impact": 8.0,
        "exploitability": "High",
    },
    "CWE-863": {
        "name": "Incorrect Authorization",
        "base_impact": 8.0,
        "exploitability": "High",
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "base_impact": 9.0,
        "exploitability": "Critical",
    },
    "CWE-284": {
        "name": "Improper Access Control",
        "base_impact": 8.0,
        "exploitability": "High",
    },
    "CWE-264": {
        "name": "Permissions, Privileges, and Access Controls",
        "base_impact": 8.0,
        "exploitability": "High",
    },
    # Cryptography
    "CWE-326": {
        "name": "Inadequate Encryption Strength",
        "base_impact": 7.0,
        "exploitability": "Medium",
    },
    "CWE-327": {
        "name": "Use of Broken Crypto Algorithm",
        "base_impact": 7.5,
        "exploitability": "Medium",
    },
    "CWE-328": {
        "name": "Use of Weak Hash",
        "base_impact": 7.0,
        "exploitability": "Medium",
    },
    "CWE-330": {
        "name": "Insufficient Randomness",
        "base_impact": 6.5,
        "exploitability": "Medium",
    },
    "CWE-311": {
        "name": "Missing Encryption of Sensitive Data",
        "base_impact": 7.5,
        "exploitability": "Medium",
    },
    "CWE-312": {
        "name": "Cleartext Storage of Sensitive Information",
        "base_impact": 7.0,
        "exploitability": "Medium",
    },
    # Deserialization & Data Handling
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "base_impact": 9.0,
        "exploitability": "High",
    },
    "CWE-434": {
        "name": "Unrestricted Upload of Dangerous File Type",
        "base_impact": 9.0,
        "exploitability": "High",
    },
    "CWE-22": {"name": "Path Traversal", "base_impact": 8.0, "exploitability": "High"},
    # Resource Management
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption (DoS)",
        "base_impact": 6.0,
        "exploitability": "Medium",
    },
    "CWE-770": {
        "name": "Allocation of Resources Without Limits",
        "base_impact": 6.5,
        "exploitability": "Medium",
    },
    "CWE-674": {
        "name": "Uncontrolled Recursion",
        "base_impact": 6.0,
        "exploitability": "Medium",
    },
    "CWE-908": {
        "name": "Use of Uninitialized Resource",
        "base_impact": 7.0,
        "exploitability": "Medium",
    },
    # Information Disclosure
    "CWE-200": {
        "name": "Information Exposure",
        "base_impact": 5.5,
        "exploitability": "Low",
    },
    "CWE-209": {
        "name": "Information Exposure Through Error Message",
        "base_impact": 5.0,
        "exploitability": "Low",
    },
    "CWE-532": {
        "name": "Insertion of Sensitive Information into Log File",
        "base_impact": 5.5,
        "exploitability": "Low",
    },
    # Web Security
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "base_impact": 7.0,
        "exploitability": "Medium",
    },
    "CWE-601": {
        "name": "Open Redirect",
        "base_impact": 6.0,
        "exploitability": "Medium",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "base_impact": 8.5,
        "exploitability": "High",
    },
    "CWE-444": {
        "name": "HTTP Request Smuggling",
        "base_impact": 8.5,
        "exploitability": "High",
    },
    "CWE-639": {
        "name": "Authorization Bypass Through User-Controlled Key",
        "base_impact": 8.0,
        "exploitability": "High",
    },
    "CWE-617": {
        "name": "Reachable Assertion",
        "base_impact": 5.5,
        "exploitability": "Low",
    },
    # Logic Errors
    "CWE-362": {
        "name": "Race Condition",
        "base_impact": 7.5,
        "exploitability": "Medium",
    },
    "CWE-369": {
        "name": "Divide By Zero",
        "base_impact": 5.5,
        "exploitability": "Medium",
    },
    "CWE-754": {
        "name": "Improper Check for Unusual or Exceptional Conditions",
        "base_impact": 6.5,
        "exploitability": "Medium",
    },
}


def get_cwe_info(cwe_id: str) -> Dict[str, Any]:
    """Get CWE information and impact factor"""
    cwe_id = cwe_id.upper().strip()
    if cwe_id in CWE_IMPACT_DB:
        return CWE_IMPACT_DB[cwe_id]
    return {"name": "Unknown CWE", "base_impact": 5.0, "exploitability": "Unknown"}


def calculate_exploit_impact(
    cvss_score: float, severity: str, cwes: List[str], asset_type: str
) -> Dict[str, Any]:
    """Calculate comprehensive exploit impact factor"""

    # Base score from CVSS
    base_score = cvss_score if cvss_score else 5.0

    # CWE multiplier
    cwe_multiplier = 1.0
    max_cwe_impact = 0
    if cwes:
        for cwe in cwes:
            cwe_info = get_cwe_info(cwe)
            max_cwe_impact = max(max_cwe_impact, cwe_info["base_impact"])
        cwe_multiplier = 1 + (max_cwe_impact / 10)

    # Asset criticality multiplier
    asset_multipliers = {
        "web_application": 1.3,
        "api_endpoint": 1.4,
        "database": 1.5,
        "authentication": 1.6,
        "container": 1.2,
        "dependency": 1.1,
        "server_config": 1.2,
        "unknown": 1.0,
    }
    asset_mult = asset_multipliers.get(asset_type, 1.0)

    # Calculate final impact
    final_impact = base_score * cwe_multiplier * asset_mult

    # Determine impact level
    if final_impact >= 9.0:
        impact_level = "CRITICAL"
        priority = "P0 - Immediate"
    elif final_impact >= 7.0:
        impact_level = "HIGH"
        priority = "P1 - Urgent (24-48h)"
    elif final_impact >= 5.0:
        impact_level = "MEDIUM"
        priority = "P2 - Important (1 week)"
    elif final_impact >= 3.0:
        impact_level = "LOW"
        priority = "P3 - Normal (1 month)"
    else:
        impact_level = "INFO"
        priority = "P4 - Monitor"

    return {
        "score": round(final_impact, 2),
        "level": impact_level,
        "priority": priority,
        "cvss_base": base_score,
        "cwe_factor": round(cwe_multiplier, 2),
        "asset_factor": asset_mult,
    }


def determine_asset_type(finding: Dict[str, Any], source: str) -> str:
    """Determine asset type from finding"""
    if source == "zap":
        alert = finding.get("alert", "").lower()
        if "sql" in alert or "injection" in alert:
            return "database"
        elif "auth" in alert or "session" in alert or "cookie" in alert:
            return "authentication"
        elif "xss" in alert or "script" in alert:
            return "web_application"
        else:
            return "web_application"
    elif source == "trivy":
        pkg = finding.get("pkg", "").lower()
        if any(db in pkg for db in ["mysql", "postgres", "mongo", "redis"]):
            return "database"
        else:
            return "dependency"
    elif source == "nuclei":
        tags = finding.get("tags", [])
        if isinstance(tags, list):
            if any(t in tags for t in ["auth", "login"]):
                return "authentication"
            elif "api" in tags:
                return "api_endpoint"
        return "web_application"
    else:
        return "unknown"


def generate_assessment_guidance(
    cve: str,
    cwes: List[str],
    asset_type: str,
    vulnerability_name: str,
    impact: Dict[str, Any],
) -> Dict[str, Any]:
    """Generate detailed assessment and remediation guidance"""

    primary_cwe = cwes[0] if cwes else "CWE-Unknown"
    cwe_info = get_cwe_info(primary_cwe)

    # Assessment steps based on CWE type
    assessment_steps = []
    remediation_steps = []

    if "SQL Injection" in cwe_info["name"] or "CWE-89" in primary_cwe:
        assessment_steps = [
            "Test with SQL payloads (', --, /*)",
            "Verify parameterized queries usage",
            "Check input validation and sanitization",
            "Test with SQLMap or manual injection",
            "Verify database error messages exposure",
        ]
        remediation_steps = [
            "Implement parameterized queries/prepared statements",
            "Use ORM frameworks with built-in protections",
            "Apply principle of least privilege to DB accounts",
            "Enable WAF rules for SQL injection",
            "Sanitize and validate all user inputs",
        ]
    elif "XSS" in cwe_info["name"] or "CWE-79" in primary_cwe:
        assessment_steps = [
            "Test with XSS payloads (<script>, onerror=)",
            "Check Content-Security-Policy headers",
            "Verify output encoding implementation",
            "Test both reflected and stored XSS",
            "Check DOM-based XSS vulnerabilities",
        ]
        remediation_steps = [
            "Implement output encoding (HTML, JS, URL contexts)",
            "Set strict Content-Security-Policy headers",
            "Use HTTPOnly and Secure flags on cookies",
            "Validate and sanitize all user inputs",
            "Use modern frameworks with auto-escaping",
        ]
    elif "Command Injection" in cwe_info["name"] or "CWE-78" in primary_cwe:
        assessment_steps = [
            "Test with OS command payloads (;, &&, |)",
            "Check input validation for special characters",
            "Verify if shell execution is necessary",
            "Test command chaining and substitution",
            "Check file system access controls",
        ]
        remediation_steps = [
            "Avoid shell execution; use language APIs directly",
            "Implement strict input whitelist validation",
            "Use parameterized APIs (subprocess with list args)",
            "Apply principle of least privilege",
            "Sanitize all inputs used in system calls",
        ]
    elif "Authentication" in cwe_info["name"]:
        assessment_steps = [
            "Test authentication bypass techniques",
            "Check for default credentials",
            "Verify session management implementation",
            "Test password complexity requirements",
            "Check for multi-factor authentication",
        ]
        remediation_steps = [
            "Implement strong authentication mechanisms",
            "Enforce multi-factor authentication",
            "Use secure session management",
            "Implement account lockout policies",
            "Hash passwords with bcrypt/argon2",
        ]
    else:
        assessment_steps = [
            f"Review {vulnerability_name} in context",
            "Check affected component exposure",
            "Verify exploitability conditions",
            "Assess data sensitivity involved",
            "Test proof-of-concept if available",
        ]
        remediation_steps = [
            "Apply vendor security patches",
            "Update vulnerable components",
            "Implement compensating controls",
            "Review security configurations",
            "Monitor for exploitation attempts",
        ]

    return {
        "assessment_steps": assessment_steps,
        "remediation_steps": remediation_steps,
        "testing_tools": get_testing_tools(primary_cwe),
        "references": get_references(cve, primary_cwe),
    }


def get_testing_tools(cwe: str) -> List[str]:
    """Get recommended testing tools for CWE type"""
    tool_map = {
        "CWE-89": ["SQLMap", "Burp Suite", "OWASP ZAP SQL Injection scanner"],
        "CWE-79": ["XSStrike", "Burp Suite", "OWASP ZAP XSS scanner"],
        "CWE-78": ["Commix", "Burp Suite", "Manual testing"],
        "CWE-22": ["DotDotPwn", "Burp Suite Intruder", "Manual path traversal"],
        "CWE-502": ["ysoserial", "Java Deserialization Scanner", "Manual testing"],
        "CWE-352": ["Burp Suite CSRF PoC", "OWASP ZAP", "Manual testing"],
        "CWE-611": ["XXEinjector", "Burp Suite", "Manual XML testing"],
        "CWE-918": ["SSRFmap", "Burp Suite Collaborator", "Manual SSRF testing"],
    }
    return tool_map.get(cwe, ["Burp Suite", "OWASP ZAP", "Manual security testing"])


def get_references(cve: str, cwe: str) -> List[str]:
    """Generate reference links"""
    refs = []
    if cve and cve != "N/A":
        refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
    if cwe and cwe.startswith("CWE-"):
        cwe_num = cwe.split("-")[1]
        refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")
    refs.append("https://owasp.org/www-community/vulnerabilities/")
    return refs


def build_correlation_table(
    target_reports: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build comprehensive CVE-CWE-Asset-Vulnerability correlation table"""

    correlations = []

    for target, report in target_reports.items():
        # Process Trivy CVEs
        for vuln in report.get("trivy", []):
            cve = vuln.get("cve") or vuln.get("vulnerability_id") or "N/A"
            cwes = vuln.get("cwes", [])

            # Better CWE extraction
            if not cwes and vuln.get("cwe"):
                cwes = [vuln.get("cwe")]
            if isinstance(cwes, str):
                cwes = [cwes]

            # Normalize CWE format
            cwes = [
                f"CWE-{c}" if not str(c).startswith("CWE") else str(c)
                for c in cwes
                if c
            ]

            cvss = float(vuln.get("cvss_score", 0)) if vuln.get("cvss_score") else 0
            severity = vuln.get("severity", "unknown").lower()

            # Better vulnerability name extraction
            vuln_name = (
                vuln.get("title")
                or vuln.get("vulnerability")
                or vuln.get("description", "")[:80]
                or f"{cve} in {vuln.get('pkg', 'package')}"
            )

            asset_type = determine_asset_type(vuln, "trivy")
            impact = calculate_exploit_impact(cvss, severity, cwes, asset_type)
            guidance = generate_assessment_guidance(
                cve, cwes, asset_type, vuln_name, impact
            )

            correlations.append(
                {
                    "target": target,
                    "cve": cve,
                    "cwes": cwes,
                    "primary_cwe": cwes[0] if cwes else "N/A",
                    "cwe_name": get_cwe_info(cwes[0] if cwes else "")["name"],
                    "asset_type": asset_type,
                    "vulnerability": vuln_name,
                    "package": vuln.get("pkg") or vuln.get("package_name") or "N/A",
                    "version": vuln.get("version")
                    or vuln.get("installed_version")
                    or "N/A",
                    "severity": severity,
                    "cvss_score": cvss,
                    "impact": impact,
                    "guidance": guidance,
                    "source": "trivy",
                }
            )

        # Process ZAP findings
        for finding in report.get("zap", []):
            # Better CWE extraction for ZAP
            cwes = finding.get("cweid", [])
            if not cwes:
                cwes = finding.get("cwe", [])

            if isinstance(cwes, (int, str)):
                cwes = [f"CWE-{cwes}"]
            elif isinstance(cwes, list):
                cwes = [
                    f"CWE-{c}" if not str(c).startswith("CWE") else str(c)
                    for c in cwes
                    if c
                ]

            risk = finding.get("risk", "unknown").lower()
            severity_map = {
                "high": 8.0,
                "medium": 5.0,
                "low": 3.0,
                "informational": 1.0,
            }
            cvss = severity_map.get(risk, 5.0)

            # Better vulnerability name extraction
            vuln_name = (
                finding.get("alert")
                or finding.get("name")
                or finding.get("description", "")[:80]
                or "Web Application Vulnerability"
            )

            asset_type = determine_asset_type(finding, "zap")
            impact = calculate_exploit_impact(cvss, risk, cwes, asset_type)
            guidance = generate_assessment_guidance(
                "N/A", cwes, asset_type, vuln_name, impact
            )

            correlations.append(
                {
                    "target": target,
                    "cve": "N/A",
                    "cwes": cwes,
                    "primary_cwe": cwes[0] if cwes else "N/A",
                    "cwe_name": get_cwe_info(cwes[0] if cwes else "")["name"],
                    "asset_type": asset_type,
                    "vulnerability": vuln_name,
                    "package": "Web Application",
                    "version": "N/A",
                    "severity": risk,
                    "cvss_score": cvss,
                    "impact": impact,
                    "guidance": guidance,
                    "source": "zap",
                    "url": finding.get("url", ""),
                }
            )

        # Process Nuclei findings
        for finding in report.get("nuclei", []):
            # Better CWE extraction for Nuclei
            cwes = finding.get("cwes", [])
            if not cwes:
                cwes = finding.get("cwe", [])

            if isinstance(cwes, str):
                cwes = [cwes]
            cwes = [
                f"CWE-{c}" if not str(c).startswith("CWE") else str(c)
                for c in cwes
                if c
            ]

            severity = finding.get("severity", "info").lower()
            severity_map = {
                "critical": 9.5,
                "high": 8.0,
                "medium": 5.0,
                "low": 3.0,
                "info": 1.0,
            }
            cvss = severity_map.get(severity, 5.0)

            # Better vulnerability name extraction from Nuclei
            vuln_name = (
                finding.get("name") or finding.get("info", {}).get("name")
                if isinstance(finding.get("info"), dict)
                else None
                or finding.get("template_id", "").replace("-", " ").title()
                or finding.get("template-id", "").replace("-", " ").title()
                or "Security Misconfiguration"
            )

            asset_type = determine_asset_type(finding, "nuclei")
            impact = calculate_exploit_impact(cvss, severity, cwes, asset_type)
            guidance = generate_assessment_guidance(
                "N/A", cwes, asset_type, vuln_name, impact
            )

            correlations.append(
                {
                    "target": target,
                    "cve": "N/A",
                    "cwes": cwes,
                    "primary_cwe": cwes[0] if cwes else "N/A",
                    "cwe_name": get_cwe_info(cwes[0] if cwes else "")["name"],
                    "asset_type": asset_type,
                    "vulnerability": vuln_name,
                    "package": "Web Application",
                    "version": "N/A",
                    "severity": severity,
                    "cvss_score": cvss,
                    "impact": impact,
                    "guidance": guidance,
                    "source": "nuclei",
                }
            )

    # Sort by impact score descending
    correlations.sort(key=lambda x: x["impact"]["score"], reverse=True)

    return correlations


def load_target_report(target: str, reports_dir: str) -> Dict[str, Any]:
    """Load individual target report JSON"""
    report_path = os.path.join(reports_dir, target, "summary.json")
    if not os.path.exists(report_path):
        return {
            "counts": {"zap": 0, "nuclei": 0, "trivy": 0, "nikto": 0},
            "zap": [],
            "nuclei": [],
            "trivy": [],
            "nikto": [],
        }

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Error loading {report_path}: {e}")
        return {
            "counts": {"zap": 0, "nuclei": 0, "trivy": 0, "nikto": 0},
            "zap": [],
            "nuclei": [],
            "trivy": [],
            "nikto": [],
        }


def aggregate_findings_by_severity(
    all_findings: List[Dict[str, Any]], source_type: str
) -> Dict[str, int]:
    """Count findings by severity level"""
    severity_counts = defaultdict(int)

    for finding in all_findings:
        if source_type == "zap":
            sev = finding.get("risk", "").lower() or "unknown"
        elif source_type == "trivy":
            sev = finding.get("severity", "").lower() or "unknown"
        elif source_type == "nuclei":
            sev = finding.get("severity", "").lower() or "unknown"
        else:
            sev = "info"

        severity_counts[sev] += 1

    return dict(severity_counts)


def get_top_cves_across_targets(
    target_reports: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Get most critical CVEs across all targets"""
    all_cves = []

    for target, report in target_reports.items():
        for vuln in report.get("trivy", []):
            if vuln.get("cve") and vuln.get("cvss_score"):
                try:
                    cvss = float(vuln.get("cvss_score"))
                    all_cves.append(
                        {
                            "cve": vuln.get("cve"),
                            "target": target,
                            "package": vuln.get("pkg"),
                            "version": vuln.get("version"),
                            "severity": vuln.get("severity"),
                            "cvss_score": cvss,
                            "cwes": vuln.get("cwes", []),
                        }
                    )
                except (ValueError, TypeError):
                    continue

    # Sort by CVSS score descending, then by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    all_cves.sort(
        key=lambda x: (-x["cvss_score"], severity_order.get(x["severity"].lower(), 4))
    )

    return all_cves[:20]


def get_target_comparison(
    target_reports: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Compare targets by total findings and severity breakdown"""
    comparison = []

    for target, report in target_reports.items():
        counts = report.get("counts", {})
        total = sum(counts.values())

        zap_sev = aggregate_findings_by_severity(report.get("zap", []), "zap")
        trivy_sev = aggregate_findings_by_severity(report.get("trivy", []), "trivy")
        nuclei_sev = aggregate_findings_by_severity(report.get("nuclei", []), "nuclei")

        critical_high = (
            zap_sev.get("high", 0)
            + zap_sev.get("critical", 0)
            + trivy_sev.get("high", 0)
            + trivy_sev.get("critical", 0)
            + nuclei_sev.get("high", 0)
            + nuclei_sev.get("critical", 0)
        )

        comparison.append(
            {
                "target": target,
                "total_findings": total,
                "critical_high": critical_high,
                "counts": counts,
                "zap_severity": zap_sev,
                "trivy_severity": trivy_sev,
                "nuclei_severity": nuclei_sev,
            }
        )

    comparison.sort(key=lambda x: (-x["critical_high"], -x["total_findings"]))

    return comparison


def write_master_markdown(
    output_path: str,
    target_reports: Dict[str, Dict[str, Any]],
    targets: List[str],
    correlations: List[Dict[str, Any]],
):
    """Generate comprehensive multi-target markdown report with correlation table"""

    total_counts = defaultdict(int)
    for report in target_reports.values():
        for tool, count in report.get("counts", {}).items():
            total_counts[tool] += count

    top_cves = get_top_cves_across_targets(target_reports)
    target_comparison = get_target_comparison(target_reports)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# 🎯 Multi-Target Security Scan Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Targets scanned:** {len(targets)}\n\n")

        # Executive Summary
        f.write("## 📊 Executive Summary\n\n")
        f.write("### Overall Findings\n\n")
        f.write(f"- **Total ZAP findings:** {total_counts['zap']}\n")
        f.write(f"- **Total Nuclei findings:** {total_counts['nuclei']}\n")
        f.write(f"- **Total Trivy vulnerabilities:** {total_counts['trivy']}\n")
        f.write(f"- **Total Nikto findings:** {total_counts['nikto']}\n")
        f.write(f"- **Grand total:** {sum(total_counts.values())}\n\n")

        # NEW: CVE-CWE-Asset Correlation Table
        f.write("## 🔗 CVE-CWE-Asset-Vulnerability Correlation & Impact Analysis\n\n")
        f.write(
            "This table correlates vulnerabilities with their CVEs, CWEs, affected assets, "
        )
        f.write("and provides exploit impact assessment with remediation guidance.\n\n")

        # Top 30 critical findings
        f.write("### Top Critical Findings (By Impact Score)\n\n")
        f.write(
            "| # | Target | CVE | CWE | Asset Type | Vulnerability | Impact Score | Priority | Exploitability |\n"
        )
        f.write(
            "|---|--------|-----|-----|------------|---------------|--------------|----------|----------------|\n"
        )

        for i, corr in enumerate(correlations[:30], 1):
            impact = corr["impact"]
            cwe_display = corr["primary_cwe"] if corr["primary_cwe"] != "N/A" else "-"

            f.write(
                f"| {i} | {corr['target']} | {corr['cve']} | {cwe_display} | "
                f"{corr['asset_type'].replace('_', ' ').title()} | "
                f"{corr['vulnerability'][:40]}... | "
                f"**{impact['score']}** | {impact['priority']} | "
                f"{get_cwe_info(corr['primary_cwe'])['exploitability']} |\n"
            )

        f.write("\n")

        # Detailed Correlation Table with Assessment
        f.write("### Detailed Vulnerability Assessment Guide\n\n")

        for i, corr in enumerate(correlations[:15], 1):  # Top 15 detailed
            impact = corr["impact"]
            guidance = corr["guidance"]

            f.write(f"#### {i}. {corr['vulnerability']}\n\n")

            # Summary table
            f.write("| Attribute | Value |\n")
            f.write("|-----------|-------|\n")
            f.write(f"| **Target** | {corr['target']} |\n")
            f.write(f"| **CVE** | {corr['cve']} |\n")
            f.write(
                f"| **Primary CWE** | {corr['primary_cwe']} - {corr['cwe_name']} |\n"
            )
            f.write(
                f"| **Asset Type** | {corr['asset_type'].replace('_', ' ').title()} |\n"
            )
            f.write(
                f"| **Package/Component** | {corr['package']} ({corr['version']}) |\n"
            )
            f.write(f"| **Severity** | {corr['severity'].upper()} |\n")
            f.write(f"| **CVSS Base Score** | {corr['cvss_score']} |\n")
            f.write(
                f"| **Calculated Impact Score** | **{impact['score']}** ({impact['level']}) |\n"
            )
            f.write(f"| **Priority** | {impact['priority']} |\n")
            f.write(
                f"| **Exploitability** | {get_cwe_info(corr['primary_cwe'])['exploitability']} |\n"
            )
            f.write(f"| **Source Tool** | {corr['source'].upper()} |\n")
            f.write("\n")

            # Impact Calculation Breakdown
            f.write("**Impact Score Calculation:**\n")
            f.write(f"- Base CVSS: {impact['cvss_base']}\n")
            f.write(f"- CWE Risk Factor: {impact['cwe_factor']}x\n")
            f.write(f"- Asset Criticality: {impact['asset_factor']}x\n")
            f.write(f"- **Final Impact: {impact['score']}**\n\n")

            # Assessment Steps
            f.write("**Assessment Steps:**\n")
            for step in guidance["assessment_steps"]:
                f.write(f"1. {step}\n")
            f.write("\n")

            # Remediation Steps
            f.write("**Remediation Steps:**\n")
            for step in guidance["remediation_steps"]:
                f.write(f"1. {step}\n")
            f.write("\n")

            # Testing Tools
            f.write("**Recommended Testing Tools:**\n")
            for tool in guidance["testing_tools"]:
                f.write(f"- {tool}\n")
            f.write("\n")

            # References
            f.write("**References:**\n")
            for ref in guidance["references"]:
                f.write(f"- {ref}\n")
            f.write("\n")

            f.write("---\n\n")

        # Asset Type Distribution
        f.write("### 📦 Vulnerabilities by Asset Type\n\n")
        asset_dist: Dict[str, Dict[str, Any]] = {}
        for corr in correlations:
            asset_type = corr["asset_type"]
            if asset_type not in asset_dist:
                asset_dist[asset_type] = {
                    "count": 0,
                    "critical_high": 0,
                    "total_impact": 0.0,
                }
            asset_dist[asset_type]["count"] += 1
            asset_dist[asset_type]["total_impact"] += corr["impact"]["score"]
            if corr["impact"]["level"] in ["CRITICAL", "HIGH"]:
                asset_dist[asset_type]["critical_high"] += 1

        f.write("| Asset Type | Total Vulns | Critical/High | Avg Impact Score |\n")
        f.write("|------------|-------------|---------------|------------------|\n")
        for asset, data in sorted(
            asset_dist.items(), key=lambda x: x[1]["total_impact"], reverse=True
        ):
            avg_impact = (
                data["total_impact"] / data["count"] if data["count"] > 0 else 0
            )
            f.write(
                f"| {asset.replace('_', ' ').title()} | {data['count']} | "
                f"{data['critical_high']} | {avg_impact:.2f} |\n"
            )
        f.write("\n")

        # CWE Distribution
        f.write("### 🔍 Top CWE Weaknesses Found\n\n")
        cwe_dist: Dict[str, Dict[str, Any]] = {}
        for corr in correlations:
            if corr["primary_cwe"] != "N/A":
                if corr["primary_cwe"] not in cwe_dist:
                    cwe_dist[corr["primary_cwe"]] = {"count": 0, "targets": set()}
                cwe_dist[corr["primary_cwe"]]["count"] += 1
                cwe_dist[corr["primary_cwe"]]["targets"].add(corr["target"])

        f.write(
            "| CWE | Description | Occurrences | Affected Targets | Exploitability |\n"
        )
        f.write(
            "|-----|-------------|-------------|------------------|----------------|\n"
        )
        for cwe, data in sorted(
            cwe_dist.items(), key=lambda x: x[1]["count"], reverse=True
        )[:15]:
            cwe_info = get_cwe_info(cwe)
            f.write(
                f"| {cwe} | {cwe_info['name']} | {data['count']} | "
                f"{len(data['targets'])} | {cwe_info['exploitability']} |\n"
            )
        f.write("\n")

        # Target Comparison
        f.write("### 🏆 Target Risk Ranking\n\n")
        f.write(
            "| Rank | Target | Critical/High | Total Findings | ZAP | Nuclei | Trivy | Nikto |\n"
        )
        f.write(
            "|------|--------|---------------|----------------|-----|--------|-------|-------|\n"
        )

        for i, target_data in enumerate(target_comparison, 1):
            target = target_data["target"]
            counts = target_data["counts"]
            f.write(
                f"| {i} | **{target}** | {target_data['critical_high']} | {target_data['total_findings']} | "
                f"{counts.get('zap', 0)} | {counts.get('nuclei', 0)} | {counts.get('trivy', 0)} | {counts.get('nikto', 0)} |\n"
            )

        f.write("\n")

        # Top Critical CVEs
        if top_cves:
            f.write("### 🚨 Top Critical CVEs (Cross-Target)\n\n")
            f.write("| CVE | Target | CVSS | Severity | Package | Version | CWEs |\n")
            f.write("|-----|--------|------|----------|---------|---------|------|\n")

            for cve_data in top_cves:
                cwes = ", ".join(cve_data["cwes"]) if cve_data["cwes"] else "-"
                f.write(
                    f"| {cve_data['cve']} | {cve_data['target']} | {cve_data['cvss_score']:.1f} | "
                    f"{cve_data['severity']} | {cve_data['package']} | {cve_data['version']} | {cwes} |\n"
                )

            f.write("\n")

        # Detailed per-target breakdown
        f.write("## 🔍 Detailed Target Analysis\n\n")

        for target_data in target_comparison:
            target = target_data["target"]
            report = target_reports[target]

            f.write(f"### {target.upper()}\n\n")

            # Target summary
            f.write(f"**Total findings:** {target_data['total_findings']} | ")
            f.write(f"**Critical/High:** {target_data['critical_high']}\n\n")

            # Tool breakdown with severity
            f.write("#### Tool Breakdown\n\n")

            # ZAP findings
            zap_findings = report.get("zap", [])
            if zap_findings:
                f.write("**ZAP (Web Application)**\n")
                zap_high = [
                    z
                    for z in zap_findings
                    if (z.get("risk", "").lower() in ["high", "critical"])
                ]
                if zap_high:
                    f.write("High-risk alerts:\n")
                    for alert in zap_high[:5]:
                        f.write(
                            f"- {alert.get('alert', 'Unknown')} (Risk: {alert.get('risk', 'Unknown')})\n"
                        )
                    if len(zap_high) > 5:
                        f.write(
                            f"- ... and {len(zap_high) - 5} more high-risk alerts\n"
                        )
                f.write(f"Total: {len(zap_findings)} findings\n\n")

            # Trivy findings
            trivy_findings = report.get("trivy", [])
            if trivy_findings:
                f.write("**Trivy (Container/Dependencies)**\n")
                trivy_critical = [
                    t
                    for t in trivy_findings
                    if (t.get("severity", "").lower() in ["critical", "high"])
                ]
                if trivy_critical:
                    f.write("Critical/High CVEs:\n")
                    for cve in trivy_critical[:5]:
                        score = (
                            f" (CVSS: {cve.get('cvss_score', 'N/A')})"
                            if cve.get("cvss_score")
                            else ""
                        )
                        f.write(
                            f"- {cve.get('cve', 'Unknown')} - {cve.get('pkg', 'Unknown')}{score}\n"
                        )
                    if len(trivy_critical) > 5:
                        f.write(
                            f"- ... and {len(trivy_critical) - 5} more critical/high CVEs\n"
                        )
                f.write(f"Total: {len(trivy_findings)} vulnerabilities\n\n")

            # Nuclei findings
            nuclei_findings = report.get("nuclei", [])
            if nuclei_findings:
                f.write("**Nuclei (Templates)**\n")
                nuclei_high = [
                    n
                    for n in nuclei_findings
                    if (n.get("severity", "").lower() in ["critical", "high"])
                ]
                if nuclei_high:
                    f.write("High-severity templates:\n")
                    for template in nuclei_high[:3]:
                        f.write(
                            f"- {template.get('name', template.get('template_id', 'Unknown'))}\n"
                        )
                    if len(nuclei_high) > 3:
                        f.write(f"- ... and {len(nuclei_high) - 3} more\n")
                f.write(f"Total: {len(nuclei_findings)} findings\n\n")

            # Nikto findings
            nikto_findings = report.get("nikto", [])
            if nikto_findings:
                f.write(f"**Nikto (Web Server):** {len(nikto_findings)} findings\n\n")

            f.write("---\n\n")

        # Recommendations
        f.write("## 📋 Priority Recommendations\n\n")
        f.write("### Immediate Actions (Critical/High Impact)\n\n")

        # Get top 5 by impact score
        critical_findings = [
            c for c in correlations if c["impact"]["level"] in ["CRITICAL", "HIGH"]
        ][:5]

        f.write("**Top 5 vulnerabilities requiring immediate attention:**\n\n")
        for i, finding in enumerate(critical_findings, 1):
            f.write(f"{i}. **{finding['vulnerability']}** on {finding['target']}\n")
            f.write(
                f"   - Impact Score: {finding['impact']['score']} ({finding['impact']['level']})\n"
            )
            f.write(f"   - Priority: {finding['impact']['priority']}\n")
            f.write(f"   - CWE: {finding['primary_cwe']} - {finding['cwe_name']}\n")
            if finding["cve"] != "N/A":
                f.write(f"   - CVE: {finding['cve']}\n")
            f.write(
                f"   - Quick Action: {finding['guidance']['remediation_steps'][0]}\n"
            )
            f.write("\n")

        f.write("### Medium-term Actions\n\n")
        f.write(
            "- Review and remediate all high-severity web application vulnerabilities\n"
        )
        f.write("- Update vulnerable packages identified by Trivy\n")
        f.write("- Implement security headers and configurations flagged by Nuclei\n")
        f.write("- Address Nikto findings related to server configuration\n\n")

        f.write("### CWE-Based Remediation Focus\n\n")
        f.write(
            "Prioritize remediation efforts by addressing these common weakness patterns:\n\n"
        )

        for cwe, data in sorted(
            cwe_dist.items(), key=lambda x: x[1]["count"], reverse=True
        )[:5]:
            cwe_info = get_cwe_info(cwe)
            f.write(f"**{cwe} - {cwe_info['name']}** ({data['count']} occurrences)\n")
            f.write(f"- Exploitability: {cwe_info['exploitability']}\n")
            f.write(f"- Affected targets: {', '.join(sorted(data['targets']))}\n")
            f.write(f"- Base Impact Factor: {cwe_info['base_impact']}/10\n\n")

        # Footer
        f.write("---\n\n")
        f.write("### 📁 Individual Reports\n\n")
        f.write("Detailed reports for each target:\n\n")
        for target in targets:
            f.write(f"- [{target}](./reports/{target}/summary.md)\n")
        f.write("\n")

        f.write("### 📖 Impact Score Methodology\n\n")
        f.write("The Impact Score is calculated using the formula:\n\n")
        f.write(
            "```\nImpact Score = CVSS Base Score × CWE Risk Factor × Asset Criticality Factor\n```\n\n"
        )
        f.write("**Scoring Levels:**\n")
        f.write("- **CRITICAL (9.0+):** Immediate remediation required (P0)\n")
        f.write("- **HIGH (7.0-8.9):** Urgent remediation within 24-48h (P1)\n")
        f.write("- **MEDIUM (5.0-6.9):** Important remediation within 1 week (P2)\n")
        f.write("- **LOW (3.0-4.9):** Normal remediation within 1 month (P3)\n")
        f.write("- **INFO (<3.0):** Monitor and review (P4)\n\n")

        f.write("### ⚠️ Disclaimer\n\n")
        f.write("This automated scan provides an initial security assessment. ")
        f.write("Manual verification is required for all findings. ")
        f.write("False positives are possible, especially for informational findings. ")
        f.write(
            "Impact scores are calculated algorithmically and should be validated by security professionals.\n"
        )

    print(f"[+] Master markdown report written to {output_path}")


def write_master_json(
    output_path: str,
    target_reports: Dict[str, Dict[str, Any]],
    targets: List[str],
    correlations: List[Dict[str, Any]],
):
    """Generate comprehensive JSON summary with correlation data"""

    total_counts = defaultdict(int)
    for report in target_reports.values():
        for tool, count in report.get("counts", {}).items():
            total_counts[tool] += count

    master_report = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "targets": targets,
            "total_targets": len(targets),
        },
        "summary": {
            "total_counts": dict(total_counts),
            "grand_total": sum(total_counts.values()),
        },
        "correlation_table": correlations,
        "target_comparison": get_target_comparison(target_reports),
        "top_cves": get_top_cves_across_targets(target_reports),
        "individual_reports": target_reports,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(master_report, f, indent=2, ensure_ascii=False)

    print(f"[+] Master JSON report written to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Merge multi-target security scan reports with CVE-CWE-Asset correlation"
    )
    parser.add_argument("--targets", nargs="+", required=True, help="Target names")
    parser.add_argument("--reports-dir", default="reports", help="Reports directory")
    parser.add_argument(
        "--out", default="reports/master-summary.md", help="Output markdown file"
    )
    parser.add_argument(
        "--out-json", default="reports/master-summary.json", help="Output JSON file"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Print debug info about JSON structure"
    )

    args = parser.parse_args()

    # Load all target reports
    target_reports = {}
    for target in args.targets:
        print(f"[+] Loading report for {target}...")
        target_reports[target] = load_target_report(target, args.reports_dir)

        # Debug mode: show structure
        if args.debug and target_reports[target]:
            print(f"\n[DEBUG] Structure for {target}:")
            report = target_reports[target]

            if report.get("trivy"):
                print(f"  Trivy sample keys: {list(report['trivy'][0].keys())}")
                print(
                    f"  Trivy sample: {json.dumps(report['trivy'][0], indent=2)[:500]}"
                )

            if report.get("zap"):
                print(f"  ZAP sample keys: {list(report['zap'][0].keys())}")
                print(f"  ZAP sample: {json.dumps(report['zap'][0], indent=2)[:500]}")

            if report.get("nuclei"):
                print(f"  Nuclei sample keys: {list(report['nuclei'][0].keys())}")
                print(
                    f"  Nuclei sample: {json.dumps(report['nuclei'][0], indent=2)[:500]}"
                )
            print()

    # Build correlation table
    print("[+] Building CVE-CWE-Asset correlation table...")
    correlations = build_correlation_table(target_reports)
    print(f"[+] Correlated {len(correlations)} findings across all targets")

    # Generate master reports
    write_master_markdown(args.out, target_reports, args.targets, correlations)
    write_master_json(args.out_json, target_reports, args.targets, correlations)

    print(f"\n✅ Master reports generated!")
    print(
        f"📊 Scanned {len(args.targets)} targets with {sum(sum(r['counts'].values()) for r in target_reports.values())} total findings"
    )
    print(f"🔗 Generated {len(correlations)} correlated vulnerability assessments")

    # Summary stats
    critical_count = sum(1 for c in correlations if c["impact"]["level"] == "CRITICAL")
    high_count = sum(1 for c in correlations if c["impact"]["level"] == "HIGH")
    print(f"🚨 Critical findings: {critical_count} | High findings: {high_count}")

    if args.debug:
        print("\n[DEBUG] Sample correlations:")
        for i, corr in enumerate(correlations[:3], 1):
            print(f"\n{i}. {corr['vulnerability']}")
            print(f"   CVE: {corr['cve']}, CWE: {corr['primary_cwe']}")
            print(f"   Source: {corr['source']}, Asset: {corr['asset_type']}")
            print(f"   Impact: {corr['impact']['score']} ({corr['impact']['level']})")


if __name__ == "__main__":
    main()
