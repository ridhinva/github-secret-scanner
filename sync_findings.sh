#!/data/data/com.termux/files/usr/bin/bash
# sync_findings.sh — copy new findings from scanner to github-secret-findings repo
set -e

SRC="/root/tools/pentest/github-secret-scanner/findings"
DEST="/root/tools/pentest/github-secret-findings"
TOKEN="ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

cd "$DEST" || exit 1

# Copy all findings
for f in "$SRC"/*.txt "$SRC"/*.log; do
  [ -f "$f" ] && cp -f "$f" "$DEST/" 2>/dev/null
done

# Copy org subdirs (H1 reports)
for d in "$SRC"/*/; do
  [ -d "$d" ] && {
    dir=$(basename "$d")
    mkdir -p "$DEST/$dir"
    cp -f "$d"* "$DEST/$dir/" 2>/dev/null
  }
done

git add -A 2>/dev/null
# Only commit if something changed
if git diff-index --quiet HEAD -- 2>/dev/null; then
  exit 0
fi

git commit -m "auto-sync: $(date '+%Y-%m-%d %H:%M') new findings" 2>/dev/null
git push origin main 2>/dev/null
echo "[SYNC] $(date) pushed $(git diff --cached --shortstat | awk '{print $4}') file(s)"
