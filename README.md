-----

# Multi-Scanner Security Analysis Pipeline

This project provides a fully containerized, one-command pipeline to perform a comprehensive security scan on a web application. It uses a suite of popular open-source tools for both Dynamic Application Security Testing (DAST) and Software Composition Analysis (SCA), and then intelligently merges the results into a single, consolidated report in Markdown format.

The target application for this demonstration is the intentionally vulnerable **OWASP Juice Shop**.

## ✨ Features

  * **Containerized Environment**: All tools and the target application are managed via Docker Compose for easy setup and teardown.
  * **Multi-Tool Scanning**: Leverages the strengths of different scanners:
      * **OWASP ZAP**: For in-depth DAST, including passive and active scanning.
      * **Nuclei**: For fast, template-based vulnerability scanning.
      * **Nikto**: For classic web server misconfiguration checks.
      * **Trivy**: For SCA, identifying known vulnerabilities (CVEs) in OS packages and application dependencies.
  * **Automated Orchestration**: A single shell script (`full-scan.sh`) handles the entire process: starting the target, running all scans sequentially, and generating the final report.
  * **Intelligent Report Correlation**: The `merge_reports.py` script doesn't just combine reports; it actively correlates findings. For example, it links a web vulnerability found by ZAP (like a potential XSS) to an underlying package CVE found by Trivy that might be the root cause.
  * **Consolidated Reporting**: Generates a clean, readable `summary.md` file with an executive summary, prioritized findings, and detailed tables for each scanner.

---

--

## 🔧 How It Works

The pipeline follows these steps:

1.  **Start Services**: `docker compose` launches the OWASP Juice Shop target application and sets up a shared network for the scanners.
2.  **Run DAST Scans**:
    - **ZAP** runs both a passive "baseline" scan and an aggressive "full" active scan against the Juice Shop container.
    - **Nuclei** runs its extensive template library against the target URL.
    - **Nikto** performs its web server vulnerability checks.
3.  **Run SCA Scan**:
    - **Trivy** scans the `bkimminich/juice-shop` Docker image to find known vulnerabilities in its components.
4.  **Merge & Correlate**:
    - The `merge_reports.py` script is executed.
    - It parses the JSON and text outputs from all four scanners.
    - It builds an index of vulnerabilities from the Trivy report (by CVE, CWE, and package name).
    - It then iterates through the ZAP, Nuclei, and Nikto findings, using CVEs, CWEs, and fuzzy text matching to link them to the underlying vulnerabilities found by Trivy.
    - Finally, it generates `reports/summary.md` and `reports/summary.json` with all the consolidated data.

---

## 🚀 Getting Started

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed and running.
- [Docker Compose](https://docs.docker.com/compose/install/) (usually included with Docker Desktop).
- [Python 3](https://www.python.org/downloads/) to run the merging script.
- `git` to clone the repository.

### Quick Start

1.  **Clone the repository:**

    ```bash
    git clone <your-repo-url>
    cd <your-repo-name>
    ```

2.  **Make the script executable:**

    ```bash
    chmod +x full-scan.sh
    ```

3.  **Run the full pipeline:**

    ```bash
    ./full-scan.sh
    ```

4.  **View the results:**
    Once the script finishes, your consolidated report will be available at:
    `./reports/summary.md`

    You can also inspect the raw output from each tool in the `./reports` directory.

---

## 📂 Project Structure

```
.
├── docker-compose.yml   # Defines the services (Juice Shop, ZAP, Nuclei, Nikto)
├── full-scan.sh         # The main orchestration script that runs everything
├── merge_reports.py     # Python script to parse, correlate, and merge reports
├── reports/             # Directory for all generated reports (created on run)
└── wrk/                 # Working directory for ZAP (created on run)
```

### `docker-compose.yml`

This file defines the services used in the scan. All services are connected to a custom bridge network `scan-net` to allow them to communicate using their service names (e.g., `http://juice:3000`).

```yaml
services:
  juice:
    image: bkimminich/juice-shop:latest
    container_name: juice
    restart: unless-stopped
    ports:
      - "3000:3000"
    networks:
      - scan-net

  zap-runner:
    image: zaproxy/zap-stable:latest
    container_name: zap-runner
    working_dir: /zap
    volumes:
      - ./wrk:/zap/wrk
    networks:
      - scan-net

  nuclei:
    image: projectdiscovery/nuclei:latest
    container_name: nuclei
    volumes:
      - ./reports:/reports
    networks:
      - scan-net

  nikto:
    image: alpine/nikto:latest
    container_name: nikto
    volumes:
      - ./reports:/reports
    networks:
      - scan-net

networks:
  scan-net:
    driver: bridge
```

### `full-scan.sh`

This is the orchestrator script. **Note:** The original script had a slightly flawed method for handling Nikto's output. The version below is corrected and simplified.

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(pwd)"
mkdir -p wrk reports

echo "1) Starting Juice Shop..."
docker compose up -d juice
# wait for juice to be ready
echo -n "Waiting for Juice Shop..."
until curl -sS http://localhost:3000/ | grep -qi "juice"; do
  echo -n "."
  sleep 1
done
echo " ready."

echo "2) Run ZAP baseline (fast, passive)"
# We allow this to fail (non-zero exit) if it finds issues
docker compose run --rm zap-runner \
  /zap/zap-baseline.py \
  -t http://juice:3000 \
  -r baseline-report.html \
  -J baseline-report.json \
  -z "-config api.disablekey=true" || true

echo "3) Run ZAP full scan (active, noisy)"
docker compose run --rm zap-runner \
  /zap/zap-full-scan.py \
  -t http://juice:3000 \
  -r full-scan.html \
  -J full-scan.json \
  -z "-config api.disablekey=true -config scanner.threadPerHost=5" || true
# Move reports to the final destination
mv wrk/full-scan.html reports/ 2>/dev/null || true
mv wrk/full-scan.json reports/ 2>/dev/null || true

echo "4) Run Nuclei (templates)"
docker compose run --rm nuclei -update-templates || true
docker compose run --rm nuclei -u http://juice:3000 -jsonl -o /reports/nuclei.json || true

echo "5) Run Nikto (classic)"
# The volume mount handles placing the report directly in the ./reports folder.
docker compose run --rm nikto \
  -h http://juice:3000 \
  -o /reports/nikto.txt \
  -Format txt || true

echo "6) Trivy image scan (SCA)"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$ROOT/reports":/report \
  aquasec/trivy image --format json -o /report/trivy.json bkimminich/juice-shop:latest || true

echo "7) Merge reports into reports/summary.md"
python3 merge_reports.py \
  --zap reports/full-scan.json \
  --trivy reports/trivy.json \
  --nuclei reports/nuclei.json \
  --nikto reports/nikto.txt \
  --out reports/summary.md \
  --out-json reports/summary.json

echo "✅ All done. Reports written to ./reports"
echo "➡️ Open your summary: file://$(pwd)/reports/summary.md"
```

### `merge_reports.py`

This Python script is the core of the reporting engine. It requires no external libraries and performs the following actions:

1.  **Loads Data**: Safely loads JSON, JSONL, and text reports from the `./reports` directory.
2.  **Parses & Normalizes**: Converts the output of each tool into a standardized Python dictionary format.
3.  **Correlates**: Links DAST findings (ZAP, Nuclei) to SCA vulnerabilities (Trivy) based on shared CVE/CWE identifiers and fuzzy matching of package names from tags and descriptions.
4.  **Generates Reports**: Writes the final consolidated findings into a well-structured Markdown file and a comprehensive JSON file.
