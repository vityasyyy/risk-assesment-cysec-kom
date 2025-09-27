# 🎯 Multi-Target Security Scan Report

**Generated:** 2025-09-27 18:20:50
**Targets scanned:** 4

## 📊 Executive Summary

### Overall Findings

- **Total ZAP findings:** 41
- **Total Nuclei findings:** 3
- **Total Trivy vulnerabilities:** 2832
- **Total Nikto findings:** 269
- **Grand total:** 3145

### 🏆 Target Risk Ranking

| Rank | Target | Critical/High | Total Findings | ZAP | Nuclei | Trivy | Nikto |
|------|--------|---------------|----------------|-----|--------|-------|-------|
| 1 | **dvwa** | 805 | 1629 | 24 | 0 | 1575 | 30 |
| 2 | **webgoat** | 314 | 827 | 1 | 0 | 818 | 8 |
| 3 | **juice** | 31 | 250 | 16 | 0 | 70 | 164 |
| 4 | **mutillidae** | 6 | 439 | 0 | 3 | 369 | 67 |

### 🚨 Top Critical CVEs (Cross-Target)

| CVE | Target | CVSS | Severity | Package | Version | CWEs |
|-----|--------|------|----------|---------|---------|------|
| CVE-2023-32314 | juice | 10.0 | CRITICAL | vm2 | 3.9.17 | CWE-74 |
| CVE-2023-37466 | juice | 10.0 | CRITICAL | vm2 | 3.9.17 | CWE-94 |
| CVE-2023-37903 | juice | 10.0 | CRITICAL | vm2 | 3.9.17 | CWE-78 |
| CVE-2005-2541 | webgoat | 10.0 | LOW | tar | 1.34+dfsg-1 | - |
| CVE-2021-21345 | webgoat | 9.9 | MEDIUM | com.thoughtworks.xstream:xstream | 1.4.5 | CWE-94, CWE-502, CWE-78 |
| CVE-2015-9235 | juice | 9.8 | CRITICAL | jsonwebtoken | 0.1.0 | CWE-20, CWE-327 |
| CVE-2015-9235 | juice | 9.8 | CRITICAL | jsonwebtoken | 0.4.0 | CWE-20, CWE-327 |
| CVE-2021-26691 | dvwa | 9.8 | CRITICAL | apache2 | 2.4.25-3+deb9u5 | CWE-122, CWE-787 |
| CVE-2021-39275 | dvwa | 9.8 | CRITICAL | apache2 | 2.4.25-3+deb9u5 | CWE-787 |
| CVE-2021-44790 | dvwa | 9.8 | CRITICAL | apache2 | 2.4.25-3+deb9u5 | CWE-787 |
| CVE-2022-22720 | dvwa | 9.8 | CRITICAL | apache2 | 2.4.25-3+deb9u5 | CWE-444 |
| CVE-2022-23943 | dvwa | 9.8 | CRITICAL | apache2 | 2.4.25-3+deb9u5 | CWE-190, CWE-787 |
| CVE-2021-26691 | dvwa | 9.8 | CRITICAL | apache2-bin | 2.4.25-3+deb9u5 | CWE-122, CWE-787 |
| CVE-2021-39275 | dvwa | 9.8 | CRITICAL | apache2-bin | 2.4.25-3+deb9u5 | CWE-787 |
| CVE-2021-44790 | dvwa | 9.8 | CRITICAL | apache2-bin | 2.4.25-3+deb9u5 | CWE-787 |
| CVE-2022-22720 | dvwa | 9.8 | CRITICAL | apache2-bin | 2.4.25-3+deb9u5 | CWE-444 |
| CVE-2022-23943 | dvwa | 9.8 | CRITICAL | apache2-bin | 2.4.25-3+deb9u5 | CWE-190, CWE-787 |
| CVE-2021-26691 | dvwa | 9.8 | CRITICAL | apache2-data | 2.4.25-3+deb9u5 | CWE-122, CWE-787 |
| CVE-2021-39275 | dvwa | 9.8 | CRITICAL | apache2-data | 2.4.25-3+deb9u5 | CWE-787 |
| CVE-2021-44790 | dvwa | 9.8 | CRITICAL | apache2-data | 2.4.25-3+deb9u5 | CWE-787 |

## 🔍 Detailed Target Analysis

### DVWA

**Total findings:** 1629 | **Critical/High:** 805

#### Tool Breakdown

**ZAP (Web Application)**
Total: 24 findings

**Trivy (Container/Dependencies)**
Critical/High CVEs:
- CVE-2019-10082 - apache2 (CVSS: 9.1)
- CVE-2021-26691 - apache2 (CVSS: 9.8)
- CVE-2021-39275 - apache2 (CVSS: 9.8)
- CVE-2021-40438 - apache2 (CVSS: 9)
- CVE-2021-44790 - apache2 (CVSS: 9.8)
- ... and 800 more critical/high CVEs
Total: 1575 vulnerabilities

**Nikto (Web Server):** 30 findings

---

### WEBGOAT

**Total findings:** 827 | **Critical/High:** 314

#### Tool Breakdown

**ZAP (Web Application)**
Total: 1 findings

**Trivy (Container/Dependencies)**
Critical/High CVEs:
- CVE-2022-3715 - bash (CVSS: 7.8)
- CVE-2022-1664 - dpkg (CVSS: 9.8)
- CVE-2022-1304 - e2fsprogs (CVSS: 7.8)
- CVE-2022-1271 - gzip (CVSS: 8.8)
- CVE-2022-3534 - libbpf0 (CVSS: 8)
- ... and 309 more critical/high CVEs
Total: 818 vulnerabilities

**Nikto (Web Server):** 8 findings

---

### JUICE

**Total findings:** 250 | **Critical/High:** 31

#### Tool Breakdown

**ZAP (Web Application)**
Total: 16 findings

**Trivy (Container/Dependencies)**
Critical/High CVEs:
- CVE-2025-4802 - libc6
- NSWG-ECO-428 - base64url
- CVE-2024-4068 - braces
- CVE-2023-46233 - crypto-js (CVSS: 9.1)
- CVE-2020-15084 - express-jwt (CVSS: 9.1)
- ... and 26 more critical/high CVEs
Total: 70 vulnerabilities

**Nikto (Web Server):** 164 findings

---

### MUTILLIDAE

**Total findings:** 439 | **Critical/High:** 6

#### Tool Breakdown

**Trivy (Container/Dependencies)**
Critical/High CVEs:
- CVE-2019-3462 - apt (CVSS: 8.1)
- CVE-2019-3462 - apt-utils (CVSS: 8.1)
- CVE-2018-11235 - git (CVSS: 7.8)
- CVE-2018-11235 - git-man (CVSS: 7.8)
- CVE-2019-3462 - libapt-inst1.5 (CVSS: 8.1)
- ... and 1 more critical/high CVEs
Total: 369 vulnerabilities

**Nuclei (Templates)**
Total: 3 findings

**Nikto (Web Server):** 67 findings

---

## 📋 Priority Recommendations

### Immediate Actions (Critical/High)

1. **Address Top CVEs:** Focus on the highest CVSS scoring vulnerabilities:
   - CVE-2023-32314 on juice (CVSS: 10.0)
   - CVE-2023-37466 on juice (CVSS: 10.0)
   - CVE-2023-37903 on juice (CVSS: 10.0)

2. **Target Prioritization:** Based on risk ranking above, focus efforts on:
   - dvwa (805 critical/high findings)
   - webgoat (314 critical/high findings)
   - juice (31 critical/high findings)

### Medium-term Actions

- Review and remediate all high-severity web application vulnerabilities
- Update vulnerable packages identified by Trivy
- Implement security headers and configurations flagged by Nuclei
- Address Nikto findings related to server configuration

---

### 📁 Individual Reports

Detailed reports for each target:

- [juice](./reports/juice/summary.md)
- [dvwa](./reports/dvwa/summary.md)
- [webgoat](./reports/webgoat/summary.md)
- [mutillidae](./reports/mutillidae/summary.md)

### ⚠️ Disclaimer

This automated scan provides an initial security assessment. Manual verification is required for all findings. False positives are possible, especially for informational findings.
