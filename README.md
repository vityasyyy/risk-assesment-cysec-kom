````markdown
# Multi-Target Security Analysis Pipeline

This project provides a fully containerized, one-command pipeline to perform a comprehensive security scan on multiple web applications simultaneously. It uses a suite of popular open-source tools for both Dynamic Application Security Testing (DAST) and Software Composition Analysis (SCA), and then intelligently merges the results into individual and consolidated reports in Markdown format.

The target applications for this demonstration are four intentionally vulnerable web applications:

- **OWASP Juice Shop**
- **Damn Vulnerable Web Application (DVWA)**
- **OWASP WebGoat**
- **OWASP Mutillidae II**

## ✨ Features

- **Containerized Environment**: All tools and target applications are managed via Docker Compose for easy setup and teardown.
- **Multi-Target Scanning**: Scans multiple web applications in parallel, saving time and effort.
- **Multi-Tool Scanning**: Leverages the strengths of different scanners:
  - **OWASP ZAP**: For in-depth DAST, including passive and active scanning.
  - **Nuclei**: For fast, template-based vulnerability scanning.
  - **Nikto**: For classic web server misconfiguration checks.
  - **Trivy**: For SCA, identifying known vulnerabilities (CVEs) in OS packages and application dependencies.
- **Automated Orchestration**: A single shell script (`multiscan.sh`) handles the entire process: starting the targets, running all scans sequentially and in parallel, and generating the final reports.
- **Intelligent Report Correlation**: The `merge_reports.py` script doesn't just combine reports; it actively correlates findings. For example, it links a web vulnerability found by ZAP (like a potential XSS) to an underlying package CVE found by Trivy that might be the root cause.
- **Consolidated Reporting**: Generates a clean, readable `summary.md` file for each target, as well as a `master-summary.md` that provides a high-level overview of the security posture of all targets.

---

## 🔧 How It Works

The pipeline follows these steps:

1.  **Start Services**: `docker compose` launches the four target applications (Juice Shop, DVWA, WebGoat, and Mutillidae) and sets up a shared network for the scanners.
2.  **Run DAST Scans**:
    - **ZAP** runs both a passive "baseline" scan and an aggressive "full" active scan against each target container.
    - **Nuclei** runs its extensive template library against each target URL in parallel.
    - **Nikto** performs its web server vulnerability checks against each target in parallel.
3.  **Run SCA Scan**:
    - **Trivy** scans the Docker image of each target application to find known vulnerabilities in its components.
4.  **Merge & Correlate**:
    - The `merge_reports.py` script is executed for each target.
    - It parses the JSON and text outputs from all four scanners.
    - It builds an index of vulnerabilities from the Trivy report (by CVE, CWE, and package name).
    - It then iterates through the ZAP, Nuclei, and Nikto findings, using CVEs, CWEs, and fuzzy text matching to link them to the underlying vulnerabilities found by Trivy.
    - Finally, it generates a `reports/<target>/summary.md` and `reports/<target>/summary.json` with all the consolidated data for each target.
5.  **Generate Master Report**:
    - The `merge_reports_multi.py` script is executed.
    - It aggregates the individual summary reports.
    - It generates a `reports/master-summary.md` and `reports/master-summary.json` that provides a high-level overview of all targets, including a risk ranking and a list of the top critical CVEs across all applications.

---

## 🚀 Getting Started

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed and running.
- [Docker Compose](https://docs.docker.com/compose/install/) (usually included with Docker Desktop).
- [Python 3](https://www.python.org/downloads/) to run the merging scripts.
- `git` to clone the repository.

### Quick Start

1.  **Clone the repository:**

    ```bash
    git clone [https://github.com/vityasyyy/risk-assesment-cysec-kom.git](https://github.com/vityasyyy/risk-assesment-cysec-kom.git)
    cd risk-assesment-cysec-kom
    ```

2.  **Make the script executable:**

    ```bash
    chmod +x multiscan.sh
    ```

3.  **Run the full pipeline:**

    ```bash
    ./multiscan.sh
    ```

4.  **View the results:**
    Once the script finishes, your consolidated reports will be available at:
    - **Master Report**: `./reports/master-summary.md`
    - **Individual Reports**: `./reports/<target>/summary.md` (e.g., `./reports/juice/summary.md`)

    You can also inspect the raw output from each tool in the `./reports/<target>` directories.

---

## 📂 Project Structure
````

.
├── compose.yml \# Defines the services (targets and scanners)
├── multiscan.sh \# The main orchestration script that runs everything
├── merge_reports.py \# Python script to parse, correlate, and merge reports for a single target
├── merge_reports_multi.py \# Python script to generate a master report from individual summary reports
├── reports/ \# Directory for all generated reports (created on run)
│ ├── dvwa/
│ ├── juice/
│ ├── mutillidae/
│ ├── webgoat/
│ ├── master-summary.md
│ └── master-summary.json
└── wrk/ \# Working directory for ZAP (created on run)

```

```
