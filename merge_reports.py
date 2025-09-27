#!/usr/bin/env python3
import json, argparse, sys, os
from collections import defaultdict


def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def summarize_zap(zap_json):
    if not zap_json:
        return []
    alerts = []
    for site in zap_json.get("site", []):
        for a in site.get("alerts", []):
            alerts.append(
                {
                    "alert": a.get("alert"),
                    "risk": a.get("risk"),
                    "cwe": a.get("cweid"),
                    "confidence": a.get("confidence"),
                    "url": (a.get("instances") or [{}])[0].get("uri"),
                    "evidence": a.get("instances")[0].get("evidence")
                    if a.get("instances")
                    else None,
                }
            )
    # sort by risk (HIGH first)
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    alerts.sort(key=lambda x: order.get(x["risk"], 4))
    return alerts


def summarize_trivy(trivy_json):
    if not trivy_json:
        return []
    vulns = []
    for res in trivy_json.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            vulns.append(
                {
                    "vuln": v.get("VulnerabilityID"),
                    "pkg": v.get("PkgName"),
                    "version": v.get("InstalledVersion"),
                    "severity": v.get("Severity"),
                    "cvss": None,
                }
            )
            # attempt to pull CVSS score
            cvss = v.get("CVSS") or {}
            # prefer NVD v3
            nvd = cvss.get("NVD", {})
            if nvd:
                vulns[-1]["cvss"] = nvd.get("V3Vector") or nvd.get("V3Score") or None
    # sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulns.sort(key=lambda x: sev_order.get(x["severity"], 5))
    return vulns


def correlate(zap_alerts, trivy_vulns):
    # rough correlation: if CVE string appears in ZAP evidence or URL, attach it
    cves_by_pkg = defaultdict(list)
    for v in trivy_vulns:
        cves_by_pkg[v["vuln"]].append(v)

    correlated = []
    for a in zap_alerts:
        matches = []
        text = " ".join([str(a.get("evidence") or ""), str(a.get("url") or "")]).lower()
        for cve, items in cves_by_pkg.items():
            if cve.lower() in text:
                matches.extend(items)
        correlated.append((a, matches))
    return correlated


def write_md(outpath, zap_alerts, trivy_vulns, correlated):
    with open(outpath, "w", encoding="utf-8") as f:
        f.write("# Scan summary\n\n")
        f.write("## ZAP high/medium findings\n\n")
        for a in zap_alerts[:50]:
            f.write(
                f"- **{a['risk']}**: {a['alert']}  \n  URL: {a.get('url')}  \n  CWE: {a.get('cwe')}  \n  Evidence: {a.get('evidence')}\n\n"
            )
        f.write("\n## Trivy top vulns (CRITICAL/HIGH)\n\n")
        for v in trivy_vulns[:100]:
            f.write(
                f"- **{v['severity']}** {v['vuln']} — {v['pkg']}@{v['version']}  CVSS: {v.get('cvss')}\n"
            )
        f.write("\n## Correlated ZAP -> CVE (rough match)\n\n")
        for a, matches in correlated:
            if matches:
                f.write(f"- ZAP: {a['alert']} ({a['risk']}) @ {a.get('url')}\n")
                for m in matches:
                    f.write(
                        f"  - {m['vuln']} {m['pkg']} {m['severity']} CVSS:{m.get('cvss')}\n"
                    )
                f.write("\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--zap", required=False)
    p.add_argument("--trivy", required=False)
    p.add_argument("--out", default="reports/summary.md")
    args = p.parse_args()

    zap_json = load_json(args.zap) if args.zap else load_json("reports/full-scan.json")
    trivy_json = (
        load_json(args.trivy) if args.trivy else load_json("reports/trivy.json")
    )

    zap_alerts = summarize_zap(zap_json)
    trivy_vulns = summarize_trivy(trivy_json)
    correlated = correlate(zap_alerts, trivy_vulns)

    write_md(args.out, zap_alerts, trivy_vulns, correlated)
    print("Wrote", args.out)
