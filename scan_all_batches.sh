#!/usr/bin/env bash
# scan_all_batches.sh — runs ALL batch files sequentially through the night
# Designed to run once overnight to cover all P1/P2 orgs
# Cron: 0 1 * * * /root/tools/pentest/github-secret-scanner/scan_all_batches.sh >> /root/scan_logs/nightly_$(date +\%Y\%m\%d).log 2>&1

set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

BATCH_DIR="batches"
OUT_DIR="findings"
GITHUB_TOKEN="${GITHUB_TOKEN:?Set GITHUB_TOKEN}"
SCRIPT_NAME=$(basename "$0")

echo "=========================================="
echo "  NIGHTLY SCAN RUN — $(date -u)"
echo "  Token: ${GITHUB_TOKEN:0:10}..."
echo "=========================================="

scan_batch() {
    local batch_file="$1"
    local bn=$(basename "$batch_file" .txt)
    local REPORT="report_nightly_${bn}.txt"
    local H1_OUT="h1_report_${bn}.txt"
    local total_repos=$(grep -c . "$batch_file" || echo 0)

    echo ""
    echo ">>> [$SCRIPT_NAME] BATCH: $bn ($total_repos repos) — $(date)"
    echo ">>> [$SCRIPT_NAME] Batch: $batch_file"

    python3 scanner.py \
      --repos "$(tr '\n' ',' < "$batch_file" | sed 's/,$//')" \
      --github-token "$GITHUB_TOKEN" \
      --output-dir "$OUT_DIR" \
      --report "$REPORT" \
      --patterns critical 2>&1

    if [[ -f "$REPORT" ]]; then
        local findings=$(grep -c "^  \[" "$REPORT" 2>/dev/null || echo 0)
        local high=$(grep -c "^  \[HIGH\]" "$REPORT" 2>/dev/null || echo 0)
        echo ">>> [$SCRIPT_NAME] Batch $bn done: $findings findings ($high HIGH). Report: $REPORT"
        
        python3 findings_to_h1_report.py "$REPORT" --output "$H1_OUT" 2>&1 && \
            echo ">>> [$SCRIPT_NAME] H1 report → $H1_OUT"
    else
        echo ">>> [$SCRIPT_NAME] Batch $bn: no findings."
    fi
}

# Run all batches sequentially (avoid API contention)
for batch in $(ls "$BATCH_DIR"/batch_*.txt | sort); do
    scan_batch "$batch"
done

echo ""
echo "=========================================="
echo "  NIGHTLY RUN COMPLETE — $(date -u)"
echo "=========================================="
