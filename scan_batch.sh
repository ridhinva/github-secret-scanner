#!/usr/bin/env bash
# scan_batch.sh — scan one batch file against 10 critical patterns
# Usage: ./scan_batch.sh batches/batch_001.txt [--hazard HIGH]
# Cron example (every night at 2am):
#   0 2 * * * /root/tools/pentest/github-secret-scanner/scan_batch.sh /root/tools/pentest/github-secret-scanner/batches/batch_001.txt >> /root/scan_logs/batch_001.log 2>&1

set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

BATCH_FILE="${1:?Usage: scan_batch.sh <batch_file> [--hazard HIGH|MEDIUM|LOW]}"
H1_OUT="h1_report_$(date +%Y%m%d)_$(basename $BATCH_FILE .txt).txt"
REPORT="report_$(date +%Y%m%d)_$(basename $BATCH_FILE .txt).txt"
GITHUB_TOKEN="${GITHUB_TOKEN:?Set GITHUB_TOKEN env var or export in this script}"
LOG_DIR="scan_logs"
mkdir -p "$LOG_DIR"

TOTAL_REPOS=$(grep -c . "$BATCH_FILE" || echo 0)
echo "=========================================="
echo "  BATCH SCAN — $(date -u)"
echo "  Batch file: $BATCH_FILE"
echo "  Repos: $TOTAL_REPOS"
echo "=========================================="

# Run scanner on batch
python3 scanner.py \
  --repos "$(tr '\n' ',' < "$BATCH_FILE" | sed 's/,$//')" \
  --github-token "$GITHUB_TOKEN" \
  --output-dir "findings" \
  --report "$REPORT" \
  --patterns critical 2>&1 | tee "$LOG_DIR/$(basename "$BATCH_FILE" .txt)_$(date +%Y%m%d).log"

if [[ -f "$REPORT" ]]; then
    echo ""
    echo "[INFO] Generating H1 report → $H1_OUT"
    python3 findings_to_h1_report.py "$REPORT" --output "$H1_OUT" 2>&1
    echo "[DONE] H1 report: $H1_OUT"
else
    echo "[INFO] No findings to convert."
fi

echo ""
echo "Next batch: batch_$(printf '%03d' $(expr $(echo "$BATCH_FILE" | grep -o 'batch_[0-9]*' | cut -d_ -f2) + 1)).txt"
