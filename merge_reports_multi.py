#!/usr/bin/env python3

import json
import os
import argparse
from collections import defaultdict
from typing import Dict, List, Any
from datetime import datetime


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

    return all_cves[:20]  # Top 20


def get_target_comparison(
    target_reports: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Compare targets by total findings and severity breakdown"""
    comparison = []

    for target, report in target_reports.items():
        counts = report.get("counts", {})
        total = sum(counts.values())

        # Get severity breakdown for each tool
        zap_sev = aggregate_findings_by_severity(report.get("zap", []), "zap")
        trivy_sev = aggregate_findings_by_severity(report.get("trivy", []), "trivy")
        nuclei_sev = aggregate_findings_by_severity(report.get("nuclei", []), "nuclei")

        # Count critical/high findings
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

    # Sort by critical/high findings first, then total
    comparison.sort(key=lambda x: (-x["critical_high"], -x["total_findings"]))

    return comparison


def write_master_markdown(
    output_path: str, target_reports: Dict[str, Dict[str, Any]], targets: List[str]
):
    """Generate comprehensive multi-target markdown report"""

    # Calculate totals
    total_counts = defaultdict(int)
    for report in target_reports.values():
        for tool, count in report.get("counts", {}).items():
            total_counts[tool] += count

    # Get analysis data
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
                    for alert in zap_high[:5]:  # Top 5
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
                    for cve in trivy_critical[:5]:  # Top 5
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
                    for template in nuclei_high[:3]:  # Top 3
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
        f.write("### Immediate Actions (Critical/High)\n\n")

        if top_cves:
            f.write(
                "1. **Address Top CVEs:** Focus on the highest CVSS scoring vulnerabilities:\n"
            )
            for i, cve in enumerate(top_cves[:3], 1):
                f.write(
                    f"   - {cve['cve']} on {cve['target']} (CVSS: {cve['cvss_score']:.1f})\n"
                )
            f.write("\n")

        f.write(
            "2. **Target Prioritization:** Based on risk ranking above, focus efforts on:\n"
        )
        for i, target_data in enumerate(target_comparison[:3], 1):
            f.write(
                f"   - {target_data['target']} ({target_data['critical_high']} critical/high findings)\n"
            )
        f.write("\n")

        f.write("### Medium-term Actions\n\n")
        f.write(
            "- Review and remediate all high-severity web application vulnerabilities\n"
        )
        f.write("- Update vulnerable packages identified by Trivy\n")
        f.write("- Implement security headers and configurations flagged by Nuclei\n")
        f.write("- Address Nikto findings related to server configuration\n\n")

        # Footer
        f.write("---\n\n")
        f.write("### 📁 Individual Reports\n\n")
        f.write("Detailed reports for each target:\n\n")
        for target in targets:
            f.write(f"- [{target}](./reports/{target}/summary.md)\n")
        f.write("\n")

        f.write("### ⚠️ Disclaimer\n\n")
        f.write("This automated scan provides an initial security assessment. ")
        f.write("Manual verification is required for all findings. ")
        f.write(
            "False positives are possible, especially for informational findings.\n"
        )

    print(f"[+] Master markdown report written to {output_path}")


def write_master_json(
    output_path: str, target_reports: Dict[str, Dict[str, Any]], targets: List[str]
):
    """Generate comprehensive JSON summary"""

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
        "target_comparison": get_target_comparison(target_reports),
        "top_cves": get_top_cves_across_targets(target_reports),
        "individual_reports": target_reports,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(master_report, f, indent=2, ensure_ascii=False)

    print(f"[+] Master JSON report written to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Merge multi-target security scan reports"
    )
    parser.add_argument("--targets", nargs="+", required=True, help="Target names")
    parser.add_argument("--reports-dir", default="reports", help="Reports directory")
    parser.add_argument(
        "--out", default="reports/master-summary.md", help="Output markdown file"
    )
    parser.add_argument(
        "--out-json", default="reports/master-summary.json", help="Output JSON file"
    )

    args = parser.parse_args()

    # Load all target reports
    target_reports = {}
    for target in args.targets:
        print(f"[+] Loading report for {target}...")
        target_reports[target] = load_target_report(target, args.reports_dir)

    # Generate master reports
    write_master_markdown(args.out, target_reports, args.targets)
    write_master_json(args.out_json, target_reports, args.targets)

    print(f"\n✅ Master reports generated!")
    print(
        f"📊 Scanned {len(args.targets)} targets with {sum(sum(r['counts'].values()) for r in target_reports.values())} total findings"
    )


if __name__ == "__main__":
    main()
