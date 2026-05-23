#!/usr/bin/env bash
# scan_overnight.sh — sequential batch scanner for overnight runs
# Runs all batch files in batches/ directory, cron-able
# Usage:
#   GITHUB_TOKEN=ghp_xxx ./scan_overnight.sh

set -euo pipefail
export GITHUB_TOKEN="${GITHUB_TOKEN:?Set GITHUB_TOKEN env var}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

SCANNER="./scanner.py"
BATCH_DIR="./batches"
OUT_DIR="./findings"
H1_REPORTER="./findings_to_h1_report.py"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR" "$OUT_DIR"

TS=$(date +%Y%m%d_%H%M%S)
LOGFILE="$LOG_DIR/nightly_scan_${TS}.log"

echo "================================================" | tee "$LOGFILE"
echo "  OVERNIGHT BATCH SCAN — $(date -u +%Y-%m-%d %H:%M UTC)" | tee -a "$LOGFILE"
echo "  Token prefix : ${GITHUB_TOKEN:0:10}..." | tee -a "$LOGFILE"
echo "  Batches      : $(ls "$BATCH_DIR"/batch_*.txt 2>/dev/null | wc -l) files" | tee -a "$LOGFILE"
echo "  Output dir   : $OUT_DIR" | tee -a "$LOGFILE"
echo "================================================" | tee -a "$LOGFILE"

total_findings=0

for batch_file in $(ls "$BATCH_DIR"/batch_*.txt 2>/dev/null | sort); do
  bn=$(basename "$batch_file" .txt)
  repo_list=$(grep -c . "$batch_file" 2>/dev/null || echo 0)
  REPORT="$OUT_DIR/${bn}_report.txt"
  H1_OUT="$OUT_DIR/H1_${bn}_$(date +%Y%m%d).txt"

  echo "" | tee -a "$LOGFILE"
  echo "[$(date -u +%H:%M)] === BATCH: $bn | $repo_list repos ===" | tee -a "$LOGFILE"

  python3 -u "$SCANNER" \
    --repos "$(tr '\n' ',' < "$batch_file" | sed 's/,$//')" \
    --github-token "$GITHUB_TOKEN" \
    --output-dir "$OUT_DIR" \
    --report "$REPORT" \
    --max-pages 1 --max-findings 50 --no-color 2>&1 | tee -a "$LOGFILE"

  echo "" | tee -a "$LOGFILE"

  # Count findings and auto-generate H1 report
  if [[ -f "$REPORT" ]]; then
    n=$(wc -l < "$REPORT" | tr -d ' ')
    h=$(grep -c "\[HIGH\]" "$REPORT" 2>/dev/null || echo 0)
    echo "[$(date -u +%H:%M)] [$bn] DONE: total=$n findings | HIGH=$h" | tee -a "$LOGFILE"
    (( total_findings += 10#$h ))
    if [[ "$h" -gt 0 ]]; then
      echo "[$(date -u +%H:%M)] [$bn] Generating H1 report..." | tee -a "$LOGFILE"
      python3 -u "$H1_REPORTER" "$REPORT" --output "$H1_OUT" 2>&1 | tee -a "$LOGFILE"
      echo "[$(date -u +%H:%M)] [$bn] H1 report → $H1_OUT" | tee -a "$LOGFILE"
    fi
  else
    echo "[$(date -u +%H:%M)] [$bn] No report file — likely rate-limited or skipped." | tee -a "$LOGFILE"
  fi
done

echo "" | tee -a "$LOGFILE"
echo "================================================" | tee -a "$LOGFILE"
echo "  OVERNIGHT SCAN COMPLETE — $(date -u +%Y-%m-%d %H:%M UTC)" | tee -a "$LOGFILE"
echo "  Total HIGH findings across all batches: $total_findings" | tee -a "$LOGFILE"
echo "================================================" | tee -a "$LOGFILE"
