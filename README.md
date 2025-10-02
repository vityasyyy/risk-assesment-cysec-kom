# 🧪 Multi-Target Security Analysis Pipeline

This project provides a **fully containerized, one-command pipeline** for performing comprehensive security scans on multiple web applications simultaneously. It leverages a combination of industry-standard **DAST** (Dynamic Application Security Testing) and **SCA** (Software Composition Analysis) tools, then automatically **correlates and consolidates** the results into clear Markdown reports.

The demonstration targets are four intentionally vulnerable web applications:

- 🧃 **OWASP Juice Shop**
- 💥 **Damn Vulnerable Web Application (DVWA)**
- 🐐 **OWASP WebGoat**
- 🧱 **OWASP Mutillidae II**
- ⚡ **Bl1tz Store**

---

## ✨ Key Features

- **🧰 Containerized Environment**  
  All scanners and targets run via Docker Compose — no manual setup needed.

- **🌐 Multi-Target Scanning**  
  Scan multiple web applications in parallel, reducing total testing time.

- **🔬 Multi-Tool Coverage**  
  Combines the strengths of multiple scanners:
  - **OWASP ZAP** → In-depth DAST (passive & active scans)
  - **Nuclei** → Fast, template-based vulnerability scanning
  - **Nikto** → Web server misconfiguration checks
  - **Trivy** → SCA for known CVEs in OS packages & dependencies

- **🤖 One-Command Orchestration**  
  A single script (`multiscan.sh`) handles starting services, running all scans, and generating reports.

- **🧠 Intelligent Report Correlation**  
  `merge_reports.py` links application-level vulnerabilities (e.g., XSS from ZAP) to their **underlying package CVEs** found by Trivy.

- **📊 Consolidated Markdown Reporting**  
  Generates:
  - Individual reports for each target (e.g., `reports/juice/summary.md`)
  - A master overview report (`reports/master-summary.md`) with risk rankings and top critical CVEs.

---

## 🧭 Pipeline Overview

1. **Start Services**  
   Docker Compose spins up all four vulnerable targets and the scanning tools on a shared network.

2. **Run DAST Scans**
   - **ZAP** runs both passive (baseline) and active (full) scans.
   - **Nuclei** scans each target in parallel using its template library.
   - **Nikto** checks each target’s web server for misconfigurations.

3. **Run SCA Scans**  
   **Trivy** scans each target’s Docker image for known CVEs in packages and dependencies.

4. **Merge & Correlate Findings**
   - `merge_reports.py` parses all tool outputs for each target.
   - It builds a CVE/CWE/package index from Trivy results.
   - Findings from ZAP, Nuclei, and Nikto are linked to these base vulnerabilities.
   - A consolidated `summary.md` and `summary.json` are generated for each target.

5. **Generate Master Report**
   - `merge_reports_multi.py` aggregates all individual reports.
   - A `master-summary.md` and `master-summary.json` are generated, providing a cross-target overview and risk ranking.

---

## 🚀 Getting Started

### ✅ Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- [Python 3](https://www.python.org/downloads/)
- `git` (to clone the repository)

---

### ⚡ Quick Start

1. **Clone the repository**

   ```bash
   git clone https://github.com/vityasyyy/risk-assesment-cysec-kom.git
   cd risk-assesment-cysec-kom

   ```

2. **Make the script executable**

   ```bash
   chmod +x multiscan.sh
   ```

3. **Run the full pipeline**

   ```bash
   ./multiscan.sh
   ```

4. **View the results**
   - **Master Report** → `./reports/master-summary.md`
   - **Individual Reports** → `./reports/<target>/summary.md` (e.g., `./reports/juice/summary.md`)
   - Raw tool outputs are also stored in each target’s `./reports/<target>` directory.

---

## 📁 Project Structure

```
.
├── compose.yml                # Defines all target apps & scanners
├── multiscan.sh               # Orchestrates scanning & report generation
├── merge_reports.py           # Correlates & merges scan results per target
├── merge_reports_multi.py     # Aggregates all targets into a master report
├── reports/                   # Generated reports
│   ├── bl1tz_store/
│   ├── dvwa/
│   ├── juice/
│   ├── mutillidae/
│   ├── webgoat/
│   ├── master-summary.md
│   └── master-summary.json
└── wrk/                       # Working directory for ZAP
```

---

## 📝 Notes & Tips

- Each scan can take several minutes, especially the **ZAP full scan**.
- All findings are stored in JSON & Markdown — easy to parse or include in risk assessments.
- For production use, you can easily swap the vulnerable apps with your own targets.

---

## 🧠 Why This Matters

Most tools produce siloed results that make correlation painful. This pipeline:

- Automates scanning across multiple tools & targets.
- **Correlates vulnerabilities intelligently**, highlighting potential root causes.
- Outputs structured, ready-to-use Markdown reports — ideal for security reviews, risk assessments, or pentest documentation.

---

## 📜 License

MIT License. See [LICENSE](./LICENSE) for details.
