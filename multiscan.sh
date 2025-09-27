#!/usr/bin/env sh
set -e

ROOT="$(pwd)"
mkdir -p "$ROOT/wrk" "$ROOT/reports/juice" "$ROOT/reports/dvwa" "$ROOT/reports/webgoat" "$ROOT/reports/mutillidae"

# Define targets (names only)
TARGET_NAMES="juice dvwa webgoat mutillidae"

# Define per-target values using simple variables
URL_juice="http://juice:3000"
URL_dvwa="http://dvwa:80"
URL_webgoat="http://webgoat:8080"
URL_mutillidae="http://mutillidae:80"

HEALTHPORT_juice="3000"
HEALTHPORT_dvwa="8082"
HEALTHPORT_webgoat="8083"
HEALTHPORT_mutillidae="8084"

echo "🚀 Starting Multi-Container Security Scan..."
echo "Targets: $TARGET_NAMES"

echo "1) Starting target applications..."
docker compose -f compose.yml up -d juice dvwa webgoat mutillidae

echo "2) Waiting for all services to be ready..."
for target in $TARGET_NAMES; do
  printf "Waiting for %s..." "$target"
  # resolve the health port variable dynamically
  eval port=\$HEALTHPORT_$target

  timeout=120
  count=0
  until curl -sS "http://localhost:$port/" >/dev/null 2>&1; do
    printf "."
    sleep 2
    count=$((count + 2))
    if [ "$count" -ge "$timeout" ]; then
      printf " WARNING: %s may not be ready, continuing anyway\n" "$target"
      break
    fi
  done
  echo " ready."
done

# resolve URL function (POSIX)
get_url() {
  t=$1
  eval echo "\$URL_$t"
}

# Function to run ZAP scans
run_zap_scans() {
  target_name=$1
  target_url=$2

  echo "📡 Running ZAP scans for $target_name ($target_url)..."

  echo "  - ZAP baseline scan for $target_name"
  if ! docker compose -f compose.yml run --rm zap-runner \
    /zap/zap-baseline.py \
    -t "$target_url" \
    -r "baseline-$target_name.html" \
    -J "baseline-$target_name.json" \
    -z "-config api.disablekey=true"; then
    echo "    ZAP baseline for $target_name finished with findings or error, continuing..."
  fi

  sleep 10 # short pause between scans
  echo "  - ZAP full scan for $target_name"
  # put a reasonable max-time (-m) to avoid infinite running
  if ! docker compose -f compose.yml run --rm zap-runner \
    /zap/zap-full-scan.py \
    -t "$target_url" \
    -r "full-$target_name.html" \
    -J "full-$target_name.json" \
    -z "-config api.disablekey=true -config proxy.localport=8090 -config scanner.threadPerHost=2"; then
    echo "    ZAP full scan for $target_name finished with findings or error, continuing..."
  fi
  # move reports if present (container writes to , ensure volume mount in compose)
  mv "$ROOT/wrk/baseline-$target_name.html" "$ROOT/reports/$target_name/" 2>/dev/null || true
  mv "$ROOT/wrk/baseline-$target_name.json" "$ROOT/reports/$target_name/" 2>/dev/null || true
  mv "$ROOT/wrk/full-$target_name.html" "$ROOT/reports/$target_name/" 2>/dev/null || true
  mv "$ROOT/wrk/full-$target_name.json" "$ROOT/reports/$target_name/" 2>/dev/null || true
}

# Function to run Nuclei scans
run_nuclei_scans() {
  target_name=$1
  target_url=$2

  echo "🔬 Running Nuclei scan for $target_name ($target_url)..."
  # Add the -T flag here
  docker compose -f compose.yml run -T --rm nuclei \
    -u "$target_url" \ -jsonl \
    -o "/reports/$target_name/nuclei.json" \
    -t cves/,technologies/,default-logins/,exposures/,misconfiguration/,vulnerabilities/ \
    -severity critical,high,medium || true
}

# Function to run Nikto scans
run_nikto_scans() {
  target_name=$1
  target_url=$2

  echo "🔍 Running Nikto scan for $target_name ($target_url)..."
  # Add the -T flag here
  docker compose -f compose.yml run -T --rm nikto \
    -h "$target_url" \
    -o "/reports/$target_name/nikto.txt" \
    -Format txt || true
}

# Function to run Trivy scans
run_trivy_scans() {
  echo "🛡️  Running Trivy image scans..."

  # Define images to scan via variables
  IMAGE_juice="bkimminich/juice-shop:latest"
  IMAGE_dvwa="vulnerables/web-dvwa:latest"
  IMAGE_webgoat="webgoat/goatandwolf:latest"
  IMAGE_mutillidae="citizenstig/nowasp:latest"

  for target in $TARGET_NAMES; do
    eval img=\$IMAGE_$target
    echo "  - Scanning $img for $target"
    docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$ROOT/reports/$target":/report \
      aquasec/trivy image \
      --format json \
      -o "/report/trivy.json" \
      "$img" || true
  done
}

echo "3) Updating Nuclei templates..."
docker compose -f compose.yml run --rm nuclei -update-templates || true

echo "4) Running security scans for all targets..."
# ZAP scans (sequential due to resource usage)
for target in $TARGET_NAMES; do
  url=$(get_url "$target")
  run_zap_scans "$target" "$url"
done
#
# echo "5) Running Nuclei scans..."
for target in $TARGET_NAMES; do
  url=$(get_url "$target")
  run_nuclei_scans "$target" "$url" &
done
wait

echo "6) Running Nikto scans..."
for target in $TARGET_NAMES; do
  url=$(get_url "$target")
  run_nikto_scans "$target" "$url" &
done
wait

echo "7) Running Trivy scans..."
run_trivy_scans

echo "8) Generating consolidated reports..."
for target in $TARGET_NAMES; do
  echo "  - Generating report for $target"
  # Only call merge if at least one input file exists
  if [ -f "reports/$target/full-$target.json" ] || [ -f "reports/$target/trivy.json" ] || [ -f "reports/$target/nuclei.json" ] || [ -f "reports/$target/nikto.txt" ]; then
    python3 merge_reports.py \
      --zap "reports/$target/full-$target.json" \
      --trivy "reports/$target/trivy.json" \
      --nuclei "reports/$target/nuclei.json" \
      --nikto "reports/$target/nikto.txt" \
      --out "reports/$target/summary.md" \
      --out-json "reports/$target/summary.json" || true
  else
    echo "    No report inputs found for $target, skipping merge."
  fi
done

echo "  - Generating master consolidated report"
python3 merge_reports_multi.py \
  --targets $TARGET_NAMES \
  --reports-dir "reports" \
  --out "reports/master-summary.md" \
  --out-json "reports/master-summary.json" || true

echo "✅ Multi-container scan completed!"
echo ""
echo "📊 Results Summary:"
echo "├── Individual reports: ./reports/{juice,dvwa,webgoat,mutillidae}/summary.md"
echo "└── Master report: ./reports/master-summary.md"
echo ""
echo "🔍 Quick view of findings:"
for target in $TARGET_NAMES; do
  if [ -f "reports/$target/summary.json" ]; then
    total=$(jq -r '(.counts | to_entries | map(.value) | add) // 0' "reports/$target/summary.json" 2>/dev/null || echo "0")
    echo "  $target: $total total findings"
  fi
done
