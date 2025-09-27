#!/usr/bin/env bash
set -euo pipefail
ROOT="$(pwd)"
mkdir -p wrk reports reports/dc

echo "1) Starting Juice Shop + ZAP daemon..."
docker compose up -d juice zap
# wait for juice to be ready
echo -n "Waiting for Juice Shop..."
until curl -sS http://localhost:3000/ | grep -qi "juice"; do
  echo -n "."
  sleep 1
done
echo " ready."

# Wait a bit for zap to finish startup
echo "Waiting for ZAP daemon to be healthy..."
sleep 6

echo "2) Run ZAP baseline (fast, passive)"
if ! docker compose run --rm zap-runner \
  /zap/zap-baseline.py \
  -t http://juice:3000 \
  -r baseline-report.html \
  -J baseline-report.json \
  -z "-config api.disablekey=true"; then
  echo "ZAP baseline finished with findings or errors (non-zero exit), continuing..."
fi

echo "3) Run ZAP full scan (active, noisy) via zap-full-scan (one-shot)"
docker compose run --rm -v "$ROOT/wrk":/zap/wrk zap-runner \
  zap-full-scan.py \
  -t http://juice:3000 \
  -r full-scan.html \
  -J full-scan.json \
  -j \
  -T 45 \
  -h zap \
  -P 8080 \
  -z "-config api.disablekey=true -config scanner.threadPerHost=5" || true
mv wrk/full-scan.html reports/ || true
mv wrk/full-scan.json reports/ || true

echo "4) Run Nuclei (templates)"
# download templates first (if you want latest, remove -update=false)
docker compose run --rm nuclei -update-templates || true
docker compose run --rm -v "$ROOT/reports":/reports nuclei \
  -u http://juice:3000 -o /reports/nuclei.txt -json >reports/nuclei.json || true

echo "5) Run Nikto (classic)"
docker compose run --rm nikto -h http://juice:3000 -output /tmp/nikto.out || true
# Move nikto output from container (quick hack: run container and copy)
CONTAINER_ID=$(docker create --name tmpnikto sullo/nikto:latest)
docker cp "${CONTAINER_ID}:/tmp/nikto.out" reports/ || true
docker rm -f "${CONTAINER_ID}" || true

echo "6) Trivy image scan (CVE + CVSS for packages)"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$ROOT/reports":/report aquasec/trivy image --format json -o /report/trivy.json bkimminich/juice-shop:latest || true

echo "7) Dependency-Check (source-level) - only useful if you have source or lockfiles"
docker run --rm -v "$ROOT":/src -v "$ROOT/reports/dc":/report owasp/dependency-check:latest --scan /src --format JSON --out /report || true

echo "8) Merge reports into reports/summary.md"
python3 merge_reports.py --zap reports/full-scan.json --trivy reports/trivy.json --out reports/summary.md || true

echo "All done. Reports written to ./reports"
echo "Open: ./reports/summary.md"
