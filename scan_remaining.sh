#!/data/data/com.termux/files/usr/bin/bash
# scan_remaining.sh — scan batches 010-019 (Google→Microsoft tail)
set +m

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

GITHUB_TOKEN="${GITHUB_TOKEN:?Set GITHUB_TOKEN env var}"
OUT_DIR="./findings"
H1_REPORTER="./findings_to_h1_report.py"
LOG="./findings/nightly_remaining.log"
mkdir -p "$OUT_DIR"

echo "[$(date -u +%Y-%m-%d %H:%M UTC)] === STARTED batches 010-019 ===" | tee "$LOG"

BATCH_FILES="
batches/batch_010.txt
batches/batch_011.txt
batches/batch_012.txt
batches/batch_013.txt
batches/batch_014.txt
batches/batch_015.txt
batches/batch_016.txt
batches/batch_017.txt
batches/batch_018.txt
batches/batch_019.txt
"

for batch_file in $BATCH_FILES; do
  [ -f "$batch_file" ] || continue
  bn=$(basename "$batch_file" .txt)
  REPORT="$OUT_DIR/${bn}_report.txt"
  H1_OUT="$OUT_DIR/H1_${bn}_$(date +%Y%m%d).txt"
  n_repos=$(grep -c . "$batch_file" 2>/dev/null || echo 0)

  echo "" | tee -a "$LOG"
  echo "[$(date -u +%H:%M)] === $bn | $n_repos repos ===" | tee -a "$LOG"

  stdbuf -oL python3 -u scanner.py \
    --repos "$(tr '\n' ',' < "$batch_file" | sed 's/,$//')" \
    --github-token "$GITHUB_TOKEN" \
    --output-dir "$OUT_DIR" \
    --report "$REPORT" \
    --max-pages 1 --max-findings 50 --no-color 2>&1 | tee -a "$LOG"

  echo "" | tee -a "$LOG"

  if [ -f "$REPORT" ]; then
    h=$(grep -c '\[HIGH\]' "$REPORT" 2>/dev/null || echo 0)
    echo "[$(date -u +%H:%M)] [$bn] DONE: HIGH=$h" | tee -a "$LOG"
    if [ "$h" -gt 0 ]; then
      python3 -u "$H1_REPORTER" "$REPORT" --output "$H1_OUT" 2>&1 | tee -a "$LOG"
    fi
    bash "$SCRIPT_DIR/sync_findings.sh" 2>&1 | tee -a "$LOG" || true
  else
    echo "[$(date -u +%H:%M)] [$bn] No report — rate-limited or empty." | tee -a "$LOG"
  fi
done

echo "" | tee -a "$LOG"
echo "[$(date -u +%H:%M)] === BATCHES 010-019 COMPLETE ===" | tee -a "$LOG"
