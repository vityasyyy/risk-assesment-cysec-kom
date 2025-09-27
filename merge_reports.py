#!/usr/bin/env python3
"""
merge_reports.py
- Loads ZAP JSON, Trivy JSON, Nuclei JSONL, Nikto text
- Summarizes each scanner's output
- Correlates by CVE, CWE, and technology/package fingerprints
- Produces a human-friendly Markdown summary and a machine JSON summary
"""

import json
import os
import re
import argparse
from collections import defaultdict, Counter
from typing import Any, Dict, List, Optional, Tuple
from difflib import get_close_matches


# ---------------------------
# Helpers: safe loaders
# ---------------------------
def try_load_json(path: str) -> Optional[Any]:
    """Load JSON or JSONL intelligently. Return Python object or None."""
    if not path or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()
        if not text:
            return None
        # Try full JSON first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    # Fall back to JSONL: parse line-by-line
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            try:
                entries.append(json.loads(s))
            except json.JSONDecodeError as e:
                # Skip malformed line but print a helpful message
                print(f"[-] JSON decode error in {path} line {i}: {e}")
    return entries if entries else None


def try_load_text_lines(path: str) -> Optional[List[str]]:
    if not path or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()]
    return lines if lines else None


# ---------------------------
# Parsers for each tool
# ---------------------------
def summarize_zap(zap_json: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return list of dicts: alert, risk, cwe, confidence, url, evidence"""
    out = []
    if not zap_json:
        return out
    # ZAP format has "site": [ { "alerts": [...] } ]
    for site in zap_json.get("site", []):
        for a in site.get("alerts", []):
            instances = a.get("instances") or []
            uri = instances[0].get("uri") if instances else a.get("url") or None
            evidence = None
            if instances and isinstance(instances, list):
                try:
                    evidence = instances[0].get("evidence")
                except Exception:
                    evidence = None
            out.append(
                {
                    "source": "zaproxy",
                    "alert": a.get("alert"),
                    "risk": a.get("risk") or a.get("riskdesc") or "Unknown",
                    "cwe": str(a.get("cweid")) if a.get("cweid") else None,
                    "confidence": a.get("confidence"),
                    "url": uri,
                    "evidence": evidence,
                    "raw": a,
                }
            )
    return out


def summarize_trivy(trivy_json: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return list of dicts with keys: cve, pkg, version, severity, cvss_score, cvss_vector, cwes"""
    out = []
    if not trivy_json:
        return out
    # Trivy top-level: Results -> Vulnerabilities
    for res in trivy_json.get("Results", []):
        vulns = res.get("Vulnerabilities") or []
        for v in vulns:
            # Some variants use 'CVSS' -> 'NVD' or 'nvd' or 'nvd'->'V3Vector'
            cvss = v.get("CVSS") or v.get("Cvss") or {}
            cvss_nvd = cvss.get("NVD") or cvss.get("nvd") or cvss.get("nvdv3") or {}
            score = (
                cvss_nvd.get("V3Score")
                or cvss_nvd.get("V2Score")
                or cvss_nvd.get("score")
            )
            vector = cvss_nvd.get("V3Vector") or cvss_nvd.get("V2Vector") or None
            cwes = v.get("CweIDs") or v.get("CWE") or []
            if isinstance(cwes, str) and cwes:
                cwes = [cwes]
            out.append(
                {
                    "source": "trivy",
                    "cve": v.get("VulnerabilityID"),
                    "pkg": v.get("PkgName"),
                    "version": v.get("InstalledVersion"),
                    "severity": v.get("Severity"),
                    "cvss_score": score,
                    "cvss_vector": vector,
                    "cwes": [str(x) for x in (cwes or [])],
                    "raw": v,
                }
            )
    return out


def summarize_nuclei(nuclei_input: Optional[Any]) -> List[Dict[str, Any]]:
    """
    Nuclei outputs can be JSONL or a list already parsed.
    We'll normalize to: template_id, name, severity, host/matched, cve list, cwe list, tags
    """
    out = []
    if not nuclei_input:
        return out
    raw_entries = nuclei_input if isinstance(nuclei_input, list) else []
    # If passed a JSON object/array already parsed, use it; otherwise nothing
    for e in raw_entries:
        info = e.get("info") or {}
        classification = info.get("classification") or {}
        cve = (
            classification.get("cve")
            or classification.get("cve-id")
            or info.get("cve")
            or []
        )
        if isinstance(cve, str):
            cve = [cve]
        cwe = classification.get("cwe-id") or info.get("cwe") or None
        tags = info.get("tags") or info.get("reference") or []
        # matched-at or host or matched may be present
        matched = e.get("matched-at") or e.get("matched") or e.get("host") or None
        template_id = (
            e.get("templateID")
            or e.get("template-id")
            or e.get("id")
            or info.get("name")
        )
        severity = (
            (info.get("severity") or "").lower() if info.get("severity") else None
        )
        out.append(
            {
                "source": "nuclei",
                "template_id": template_id,
                "name": info.get("name"),
                "severity": severity,
                "matched": matched,
                "cve": [str(x) for x in (cve or [])],
                "cwe": str(cwe) if cwe else None,
                "tags": tags,
                "raw": e,
            }
        )
    return out


def summarize_nikto(lines: Optional[List[str]]) -> List[Dict[str, Any]]:
    out = []
    if not lines:
        return out
    # Nikto lines are free text: keep them but try to extract simple things
    for line in lines:
        # attempt to extract URL or path and risk words
        url_match = re.search(r"(https?://\S+)|(/\S+)", line)
        out.append(
            {
                "source": "nikto",
                "text": line,
                "url": url_match.group(0) if url_match else None,
                "raw": line,
            }
        )
    return out


# ---------------------------
# Correlation / matching
# ---------------------------
def build_indexes(trivy: List[Dict[str, Any]]):
    """Build quick lookup maps from Trivy data."""
    by_cve = {}
    by_pkg = defaultdict(list)
    by_cwe = defaultdict(list)
    for v in trivy:
        cve = v.get("cve")
        if cve:
            by_cve[cve] = v
        pkg = (v.get("pkg") or "").lower()
        if pkg:
            by_pkg[pkg].append(v)
        for cwe in v.get("cwes", []) or []:
            by_cwe[str(cwe)].append(v)
    return by_cve, by_pkg, by_cwe


def fuzzy_match_pkg(name: str, trivy_pkgs: List[str], cutoff=0.6) -> Optional[str]:
    """Return best fuzzy match (package name) from trivy package keys."""
    if not name or not trivy_pkgs:
        return None
    name = re.sub(r"[^a-z0-9]", "", name.lower())
    candidates = get_close_matches(name, trivy_pkgs, n=1, cutoff=cutoff)
    return candidates[0] if candidates else None


def correlate_all(
    zap: List[Dict[str, Any]],
    nuclei: List[Dict[str, Any]],
    trivy: List[Dict[str, Any]],
    nikto: List[Dict[str, Any]],
):
    by_cve, by_pkg_map, by_cwe = build_indexes(trivy)
    trivy_pkg_keys = list(by_pkg_map.keys())

    # ZAP correlations (CWE -> Trivy)
    zap_corr = []
    for z in zap:
        matches = []
        cwe = z.get("cwe")
        if cwe and cwe in by_cwe:
            matches.extend(by_cwe[cwe])
        # evidence text may contain CVE strings
        evidence = (z.get("evidence") or "") or ""
        for cve in by_cve.keys():
            if cve.lower() in evidence.lower():
                matches.append(by_cve[cve])
        zap_corr.append((z, dedupe_vulns(matches)))

    # Nuclei correlations (CVE -> Trivy, CWE -> Trivy, tags -> package)
    nuclei_corr = []
    for n in nuclei:
        matches = []
        # cve direct match
        for c in n.get("cve") or []:
            if c in by_cve:
                matches.append(by_cve[c])
        # cwe match
        ncwe = n.get("cwe")
        if ncwe and ncwe in by_cwe:
            matches.extend(by_cwe[ncwe])
        # try tags / name vs package fuzzy match
        tags = n.get("tags") or []
        candidates = []
        for t in tags if isinstance(tags, list) else [tags]:
            pkgname = re.sub(r"[^a-z0-9]", "", str(t).lower())
            fm = fuzzy_match_pkg(pkgname, trivy_pkg_keys, cutoff=0.55)
            if fm:
                candidates.extend(by_pkg_map[fm])
        # also try template_id or name
        for token in [n.get("template_id") or "", n.get("name") or ""]:
            tok = re.sub(r"[^a-z0-9]", "", token.lower())
            if tok:
                fm = fuzzy_match_pkg(tok, trivy_pkg_keys, cutoff=0.55)
                if fm:
                    candidates.extend(by_pkg_map[fm])
        matches.extend(candidates)
        nuclei_corr.append((n, dedupe_vulns(matches)))

    # Nikto: attempt to correlate presence of software/version strings to trivy packages
    nikto_corr = []
    for nk in nikto:
        matches = []
        text = nk.get("text") or ""
        # extract probable software tokens like "Apache/2.4.29" -> "apache"
        for token in re.findall(r"([A-Za-z0-9_\-]+)(?:/[\d\.]+)?", text):
            fm = fuzzy_match_pkg(token, trivy_pkg_keys, cutoff=0.6)
            if fm:
                matches.extend(by_pkg_map[fm])
        nikto_corr.append((nk, dedupe_vulns(matches)))

    return zap_corr, nuclei_corr, nikto_corr


def dedupe_vulns(vulns: List[Dict[str, Any]]):
    """Remove duplicates by CVE string, preserve order, keep best severity by sorting later if desired."""
    seen = set()
    out = []
    for v in vulns:
        c = v.get("cve") or v.get("VulnerabilityID") or json.dumps(v.get("raw", {}))
        if c in seen:
            continue
        seen.add(c)
        out.append(v)
    return out


# ---------------------------
# Reporting
# ---------------------------
SEV_ORDER = {
    "critical": 0,
    "crITICAL": 0,
    "CRITICAL": 0,
    "high": 1,
    "HIGH": 1,
    "medium": 2,
    "MEDIUM": 2,
    "low": 3,
    "LOW": 3,
    "unknown": 4,
    None: 5,
}


def severity_sort_key(item):
    sev = item.get("severity") or item.get("risk") or ""
    return SEV_ORDER.get(sev.lower() if isinstance(sev, str) else sev, 5)


def write_markdown(
    outpath: str,
    zap: List[Dict[str, Any]],
    nuclei: List[Dict[str, Any]],
    trivy: List[Dict[str, Any]],
    nikto: List[Dict[str, Any]],
    zap_corr,
    nuclei_corr,
    nikto_corr,
):
    # Summary counts
    counts = {
        "zap_total": len(zap),
        "nuclei_total": len(nuclei),
        "trivy_total": len(trivy),
        "nikto_total": len(nikto),
    }

    # Top vulnerable trivy by CVSS score (numeric if present)
    def cvss_value(v):
        s = v.get("cvss_score")
        try:
            return float(s)
        except Exception:
            return -1.0

    top_trivy = sorted(
        trivy,
        key=lambda v: (
            -(cvss_value(v) or 0),
            SEV_ORDER.get((v.get("severity") or "").lower(), 5),
        ),
    )[:25]

    with open(outpath, "w", encoding="utf-8") as f:
        f.write("# 🧭 Consolidated Security Scan Summary\n\n")
        f.write("**Auto-generated by merge_reports.py**\n\n")

        # Executive summary
        f.write("## Executive summary\n\n")
        f.write(f"- ZAP findings: **{counts['zap_total']}**\n")
        f.write(f"- Nuclei findings: **{counts['nuclei_total']}**\n")
        f.write(f"- Trivy vulnerabilities: **{counts['trivy_total']}**\n")
        f.write(f"- Nikto findings: **{counts['nikto_total']}**\n\n")

        # High level prioritized list (from Trivy CSVS + ZAP criticals)
        f.write("### Top prioritized items (quick wins)\n\n")
        # 1) Trivy criticals by CVSS
        crits = [
            v
            for v in trivy
            if (v.get("severity") or "").lower() in ("critical", "crITICAL", "CRITICAL")
        ]
        if crits:
            f.write("**Trivy - Critical CVEs**\n\n")
            for v in sorted(crits, key=lambda x: -(cvss_value(x) or 0))[:10]:
                f.write(
                    f"- {v.get('cve')} — {v.get('pkg')}@{v.get('version')} Severity: {v.get('severity')} CVSS: {v.get('cvss_score') or '-'}\n"
                )
            f.write("\n")
        # 2) ZAP - High or High-like alerts
        zhigh = [z for z in zap if (z.get("risk") or "").lower() in ("high", "high+")]
        if zhigh:
            f.write("**ZAP - High severity alerts**\n\n")
            for z in zhigh[:10]:
                f.write(f"- {z.get('alert')} @ {z.get('url')} (CWE: {z.get('cwe')})\n")
            f.write("\n")

        # Full Trivy table
        f.write("## Trivy vulnerabilities (selected)\n\n")
        f.write("| CVE | Package | Version | Severity | CVSS | CWE |\n")
        f.write("|-----|---------|---------|----------|------|-----|\n")
        for v in top_trivy:
            cwes = ", ".join(v.get("cwes") or []) or "-"
            f.write(
                f"| {v.get('cve') or '-'} | {v.get('pkg') or '-'} | {v.get('version') or '-'} | {v.get('severity') or '-'} | {v.get('cvss_score') or '-'} | {cwes} |\n"
            )
        f.write("\n")

        # ZAP details
        f.write("## ZAP findings (all)\n\n")
        f.write("| Risk | Alert | URL | CWE | Evidence | Correlated CVEs |\n")
        f.write("|------|-------|-----|-----|----------|-----------------|\n")
        for z, corr in zap_corr:
            cves = (
                ", ".join(sorted({m.get("cve") for m in corr if m.get("cve")})) or "-"
            )
            ev = (z.get("evidence") or "") or "-"
            f.write(
                f"| {z.get('risk') or '-'} | {escape_md(z.get('alert') or '-')} | {z.get('url') or '-'} | {z.get('cwe') or '-'} | {short(ev)} | {cves} |\n"
            )

        f.write("\n")

        # Nuclei details
        f.write("## Nuclei findings (all)\n\n")
        f.write("| Severity | Template | Matched | CVEs | CWE | Correlated CVEs |\n")
        f.write("|----------|----------|---------|------|-----|-----------------|\n")
        for n, corr in nuclei_corr:
            cves = (
                ", ".join(sorted({m.get("cve") for m in corr if m.get("cve")})) or "-"
            )
            n_cves = ", ".join(n.get("cve") or []) or "-"
            f.write(
                f"| {n.get('severity') or '-'} | {escape_md(n.get('template_id') or n.get('name') or '-')} | {n.get('matched') or '-'} | {n_cves} | {n.get('cwe') or '-'} | {cves} |\n"
            )

        f.write("\n")

        # Nikto raw
        if nikto:
            f.write("## Nikto findings (raw)\n\n")
            for nk, corr in nikto_corr:
                f.write(f"- {short(nk.get('text') or '-')}\n")
            f.write("\n")

        # Appendix: correlation summary
        f.write("## Correlation summary\n\n")
        f.write(
            f"- ZAP ↔ Trivy correlated issues: {sum(1 for z, c in zap_corr if c)}\n"
        )
        f.write(
            f"- Nuclei ↔ Trivy correlated issues: {sum(1 for n, c in nuclei_corr if c)}\n"
        )
        f.write("\n")

        f.write("---\n")
        f.write("### Notes & limitations\n\n")
        f.write(
            "- Correlation is heuristic: an absence of correlation does NOT mean unrelated; it often means scanners report different facets (web symptom vs package CVE).\n"
        )
        f.write(
            "- CVSS values are taken from the scanner output (Trivy). If missing, consult authoritative NVD/GHSA pages.\n"
        )
        f.write(
            "- False positives are possible (especially for passive/info findings). Verify manually before remediating.\n\n"
        )

    print(f"[+] Markdown written to {outpath}")


def short(s: Optional[str], length=80) -> str:
    if not s:
        return "-"
    s = str(s).replace("\n", " ").strip()
    return (s[: length - 3] + "...") if len(s) > length else s


def escape_md(s: str) -> str:
    # basic escape for pipe
    return str(s).replace("|", "\\|").replace("\n", " ")


def write_json_summary(
    outpath: str, zap, nuclei, trivy, nikto, zap_corr, nuclei_corr, nikto_corr
):
    summary = {
        "counts": {
            "zap": len(zap),
            "nuclei": len(nuclei),
            "trivy": len(trivy),
            "nikto": len(nikto),
        },
        "zap": zap,
        "nuclei": nuclei,
        "trivy": trivy,
        "nikto": nikto,
        "zap_correlation": [{"zap": z, "trivy_matches": c} for (z, c) in zap_corr],
        "nuclei_correlation": [
            {"nuclei": n, "trivy_matches": c} for (n, c) in nuclei_corr
        ],
    }
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"[+] JSON summary written to {outpath}")


# ---------------------------
# CLI and main
# ---------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--zap", default="reports/full-scan.json")
    p.add_argument("--trivy", default="reports/trivy.json")
    p.add_argument("--nuclei", default="reports/nuclei.json")
    p.add_argument("--nikto", default="reports/nikto.txt")
    p.add_argument("--out", default="reports/summary.md")
    p.add_argument("--out-json", default=None)
    args = p.parse_args()

    zap_json = try_load_json(args.zap)
    trivy_json = try_load_json(args.trivy)
    nuclei_json = try_load_json(args.nuclei)
    nikto_lines = try_load_text_lines(args.nikto)

    zap = summarize_zap(zap_json)
    trivy = summarize_trivy(trivy_json)
    nuclei = summarize_nuclei(nuclei_json)
    nikto = summarize_nikto(nikto_lines)

    zap_corr, nuclei_corr, nikto_corr = correlate_all(zap, nuclei, trivy, nikto)

    write_markdown(
        args.out, zap, nuclei, trivy, nikto, zap_corr, nuclei_corr, nikto_corr
    )
    if args.out_json:
        write_json_summary(
            args.out_json, zap, nuclei, trivy, nikto, zap_corr, nuclei_corr, nikto_corr
        )


if __name__ == "__main__":
    main()
