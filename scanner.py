#!/usr/bin/env python3
"""
GitHub Exposed-Secrets Scanner
Scans org/repo public code via GitHub Search API for exposed API keys,
credentials, tokens, private keys, and hardcoded secrets.

Usage examples (short commands):
  python scanner.py --orgs cia,fbi,apple,google --report report.txt
  python scanner.py --repos ridhinva/exploit-tool,ridhinva/another --output-dir findings/ --report report.txt
  python scanner.py --orgs abc-corp --github-token ghp_xxx --output-dir findings/ --report report.txt
  python scan_and_report.sh          (cron-able wrapper)
"""

import argparse, json, os, re, sys, time, textwrap
import requests
from pathlib import Path
from datetime import datetime

try:
    from colorama import Fore, Style, init as color_init
    color_init()
    USE_COLOR = True
except ImportError:
    class DummyFore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = ""
        RESET_ALL = ""
    class DummyStyle:
        BRIGHT = ""
        NORMAL = ""
    Fore = DummyFore()
    Style = DummyStyle()
    USE_COLOR = False

BASE_DIR = Path(__file__).parent.resolve()
PATTERNS_FILE    = BASE_DIR / "patterns.json"
DEFAULT_PATTERNS = [
    "aws_access_key_id", "aws_secret_access_key", "github_personal_token",
    "github_oauth_token", "github_fine_grained_pat", "slack_token",
    "stripe_live_key", "sendgrid_api_key", "private_key_rsa", "private_key_openssh",
    "password_in_config", "api_key_generic", "token_generic", "database_url",
    "postgres_conn_string", "google_api_key", "authorization_bearer",
    "jwt_token", "heroku_api_key", "cloudflare_api_token",
]
FINDINGS_DIR = BASE_DIR / "findings"
GITHUB_SEARCH_URL = "https://api.github.com/search/code"
GITHUB_REPOS_URL  = "https://api.github.com/orgs/{}/repos"
GITHUB_RAW_URL    = "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
SEARCH_ITEMS_PER_PAGE = 30
MAX_PAGES_PER_PATTERN  = 3
MAX_REPOS_PER_SEARCH   = 10        # multi-repo OR in one query
MAX_RESULTS_PER_QUERY  = 50        # cap raw file fetches per search-result page
MAX_RAW_FETCHES        = 10
NETWORK_RETRIES        = 3
NETWORK_RETRY_BASE     = 3.0    # exponential backoff base for Termux network
        # max files fetched per (batch_repos × pattern) pair
RAW_FETCH_SLEEP        = 0.5       # per-file throttle for raw.github.com
SLEEP_BETWEEN_SEARCHES = 6.5       # GitHub Code Search secondary: 10 q/min with PAT


def load_patterns():
    with open(PATTERNS_FILE) as f:
        return json.load(f)


def load_repos_and_orgs(args):
    """Load org list and resolve repos from each org if --repos not given."""
    orgs     = [o.strip() for o in args.orgs.split(",") if o.strip()] if args.orgs else []
    repos    = [r.strip() for r in args.repos.split(",") if r.strip()] if args.repos else []

    if not orgs and not repos:
        print("[ERROR] Provide --orgs or --repos")
        sys.exit(1)

    # Resolve repos from orgs
    if orgs and not repos:
        headers = make_headers(args.github_token)
        for org in orgs:
            page = 1
            while True:
                try:
                    r = requests.get(
                        GITHUB_REPOS_URL.format(org),
                        headers=headers,
                        params={"per_page": 100, "page": page},
                        timeout=15,
                    )
                    if r.status_code != 200:
                        print(f"[WARN] Cannot list repos for {org}: HTTP {r.status_code} {r.text[:120]}")
                        break
                    batch = r.json()
                    if not batch:
                        break
                    repos.extend([f"{org}/{repo['name']}" for repo in batch])
                    page += 1
                    if page > 10:
                        break
                except Exception as e:
                    print(f"[WARN] Error listing {org} repos: {e}")
                    break
        print(f"[INFO] Resolved {len(repos)} repos from orgs: {orgs}")

    return sorted(set(repos))


def make_headers(token=None):
    h = {"Accept": "application/vnd.github.v3+json", "User-Agent": "GitHub-Secret-Scanner/1.1"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def show_rate_limit(headers):
    try:
        r = requests.get("https://api.github.com/rate_limit", headers=headers, timeout=10)
        if r.ok:
            d = r.json()
            sr = d.get("resources", {}).get("search", {})
            print(f"   [RATE-LIMIT] Search: {sr.get('remaining', '?')}/{sr.get('limit', '?')} remaining "
                  f"(reset at {int(sr.get('reset',0))})")
    except Exception:
        pass


def extract_excerpt(text, match_start, match_end, radius=150):
    start = max(0, match_start - radius)
    end   = min(len(text), match_end + radius)
    snippet = text[start:end].replace("\n", " ")
    marker = "..." if start > 0 else ""
    marker_end = "..." if end < len(text) else ""
    return f"{marker}{snippet}{marker_end}"


def scan_repo(repo_slug_label, batch_repos, patterns, headers, search_requests_counter,
               max_pages=1, max_findings=10):
    """Scan a batch of repos using multi-repo OR queries for speed.

    Args:
        repo_slug_label:  Display label (first repo slug).
        batch_repos:      List of 'org/repo' strings included in one search batch.
        ...
    """
    print(f"\n{'='*70}")
    if len(batch_repos) > 1:
        print(f"{Fore.CYAN if USE_COLOR else ''}[BATCH SCAN] {len(batch_repos)} repos: {batch_repos[0]} … {batch_repos[-1]}{Fore.RESET if USE_COLOR else ''}")
    else:
        print(f"{Fore.CYAN if USE_COLOR else ''}[SCANNING] {batch_repos[0]}{Fore.RESET if USE_COLOR else ''}")
    print(f"{'='*70}")

    repo_findings = []
    seen_hashes   = set()
    # Build multi-repo query clause: repo:A repo:B ...
    repo_clause = " ".join(f"repo:{r}" for r in batch_repos)

    for pat_name, pat_data in patterns.items():
        regex   = pat_data["regex"]
        hazard  = pat_data["hazard"]
        desc    = pat_data["description"]

        q = f"{repo_clause} {pat_name}"
        for page in range(1, max_pages + 1):
            # ── Retry loop: network glitches (Termux proot) don't abort the scan ─
            resp = None
            for attempt in range(1, NETWORK_RETRIES + 1):
                try:
                    resp = requests.get(
                        GITHUB_SEARCH_URL,
                        headers=headers,
                        params={"q": q, "per_page": SEARCH_ITEMS_PER_PAGE, "page": page},
                        timeout=25,
                    )
                    search_requests_counter[0] += 1
                    break   # success
                except (requests.exceptions.ConnectionError,
                        requests.exceptions.Timeout) as net_err:
                    if attempt >= NETWORK_RETRIES:
                        print(f"[WARN] Network error ({attempt}/{NETWORK_RETRIES}) for {pat_name}: "
                              f"{type(net_err).__name__}: {str(net_err)[:60]}. Skipping this pattern.")
                        break
                    wait_s = NETWORK_RETRY_BASE ** attempt
                    print(f"[WARN] Network glitch ({attempt}/{NETWORK_RETRIES}): {type(net_err).__name__}, "
                          f"retrying in {wait_s:.0f}s…")
                    time.sleep(wait_s)
                except Exception as e:
                    print(f"[ERR] Unexpected error during search for {pat_name}: {e}")
                    break

            if resp is None:
                break  # all retries exhausted

            # ── Rate-limit handling ─
            if resp.status_code == 403:
                reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait  = max(reset - time.time(), 5) + 5
                print(f"[WAIT] Rate-limited. Sleeping {int(wait)}s...")
                time.sleep(wait)
                continue

            if resp.status_code != 200:
                print(f"[WARN] Search API {resp.status_code} for {pat_name}: {resp.text[:100]}")
                break

            # ── Parse results ─
            data  = resp.json()
            items = data.get("items", [])
            if not items:
                break

            if len(items) > MAX_RAW_FETCHES:
                print(f"    [INFO] {pat_name}: {len(items)} items — capping raw fetches at {MAX_RAW_FETCHES}")

            raw_fetches_this_pattern = 0
            for item in items:
                if raw_fetches_this_pattern >= MAX_RAW_FETCHES:
                    print(f"    [CAP] Raw fetch cap ({MAX_RAW_FETCHES}) reached for {pat_name}. Skipping remaining items.")
                    break
                path     = item.get("path", "?")
                html     = item.get("html_url", "")
                item_repo = item.get("repository", {}).get("full_name", "")
                if item_repo not in batch_repos:
                    continue
                branch   = item.get("repository", {}).get("default_branch", "main")
                raw_url  = f"https://raw.githubusercontent.com/{item_repo}/{branch}/{path}"
                try:
                    fr = requests.get(raw_url, headers=headers, timeout=15)
                    fr.raise_for_status()
                    file_text = fr.text
                    raw_fetches_this_pattern += 1
                except Exception:
                    continue

                for m in re.finditer(regex, file_text):
                    value_hash = hash(m.group(0))
                    if value_hash in seen_hashes:
                        continue
                    seen_hashes.add(value_hash)
                    if max_findings and len(repo_findings) >= max_findings:
                        break

                    lineno = file_text[:m.start()].count("\n") + 1
                    excerpt = extract_excerpt(file_text, m.start(), m.end())
                    repo_findings.append({
                        "repo": item_repo, "repo_url": html, "raw_url": raw_url,
                        "file": path, "line": lineno, "excerpt": excerpt,
                        "hazard": hazard, "secret_type": desc, "pattern": pat_name,
                    })
                    if max_findings and len(repo_findings) >= max_findings:
                        break
                if max_findings and len(repo_findings) >= max_findings:
                    break

            if len(items) < SEARCH_ITEMS_PER_PAGE:
                break
            if max_findings and len(repo_findings) >= max_findings:
                break
            time.sleep(SLEEP_BETWEEN_SEARCHES)
            continue  # next page

        # end for page

        return repo_findings


def write_repo_finding_file(repo_slug, findings, out_dir):
    org = repo_slug.split("/", 0)
    rd  = out_dir / repo_slug.replace("/", "/")
    rd.mkdir(parents=True, exist_ok=True)
    path = rd / f"{repo_slug.split('/', 1)[1]}.txt"

    lines = [],
    lines.append(f"Finding Report: {repo_slug}")
    lines.append(f"Generated: {datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f="-" * 70)
    lines.append(f"Total secrets found: {len(findings)}\n")

    for f in findings:
        lines.append(f"[{f['hazard']}] {f['secret_type']}")
        lines.append(f"  Repo:       {f['repo']}")
        lines.append(f"  File:       {f['file']}")
        lines.append(f"  Line:       {f['line']}")
        lines.append(f"  URL:        {f['repo_url']}")
        lines.append(f"  Raw:        {f['raw_url']}")
        lines.append(f"  Evidence:   {f['excerpt']}")
        lines.append(f"-" * 40)

    with open(path, "w") as out:
        out.write("\n".join(lines))
    print(f"[SAVED] {len(findings)} finding(s) → {path}")
    return path


def write_summary_report(all_findings, report_path):
    # Group by org
    by_org = {}
    for f in all_findings:
        org = f["repo"].split("/", 1)[0]
        by_org.setdefault(org, []).append(f)

    lines = []
    lines.append("=" * 70)
    lines.append("  GITHUB SECRET SCANNER — SUMMARY REPORT")
    lines.append(f"  Generated: {datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("=" * 70)
    lines.append(f"\n  Total repos scanned:    {len(set(f['repo'] for f in all_findings))}")
    lines.append(f"  Total findings:          {len(all_findings)}")
    total_high = sum(1 for f in all_findings if f['hazard'] == 'HIGH')
    total_med  = sum(1 for f in all_findings if f['hazard'] == 'MEDIUM')
    total_low  = sum(1 for f in all_findings if f['hazard'] == 'LOW')
    lines.append(f"    HIGH:   {total_high}")
    lines.append(f"    MEDIUM: {total_med}")
    lines.append(f"    LOW:    {total_low}")
    lines.append("")

    # Per-org summary
    org_totals = {}
    for org, findings in sorted(by_org.items()):
        high = sum(1 for f in findings if f['hazard'] == 'HIGH')
        med  = sum(1 for f in findings if f['hazard'] == 'MEDIUM')
        low  = sum(1 for f in findings if f['hazard'] == 'LOW')
        org_totals[org] = {**org_totals.get(org, {}), "total": len(findings), "high": high, "med": med, "low": low}

    lines.append("-" * 70)
    lines.append("  PER-ORG FINDING COUNT")
    lines.append(f"  {'Org':<30} {'Total':>6} {'HIGH':>5} {'MED':>5} {'LOW':>5}")
    lines.append("-" * 70)
    for org, counts in sorted(org_totals.items()):
        lines.append(f"  {org:<30} {counts['total']:>6} {counts['high']:>5} {counts['med'] or '':>5} {counts['low']:>5}")
    lines.append("")

    # Detailed findings per org
    for org, findings in sorted(by_org.items()):
        findings.sort(key=lambda x: (0 if x['hazard']=='HIGH' else 1 if x['hazard']=='MEDIUM' else 2))
        lines.append("=" * 70)
        lines.append(f"  ORG: {org}")
        lines.append("=" * 70)
        for f in findings:
            lines.append(f"\n  [{f['hazard']}] {f['secret_type']}")
            lines.append(f"    Repo:   {f['repo']}")
            lines.append(f"    File:   {f['file']}")
            lines.append(f"    Line:   {f['line']}")
            lines.append(f"    URL:    {f['repo_url']}")
            lines.append(f"    Evidence: {f['excerpt'][:200]}")

    lines.append("\n" + "=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)

    Path(report_path).write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[REPORT] Summary report saved → {report_path}")


def write_repo_finding_file(repo_slug, findings, out_dir):
    """Create per-repo txt file in findings/<org>/<repo>.txt"""
    org, repo = repo_slug.split("/", 1)
    rd = out_dir / org
    rd.mkdir(parents=True, exist_ok=True)
    fpath = rd / f"{repo}.txt"

    lines = []
    lines.append("=" * 70)
    lines.append(f"  SECRET FINDINGS: {repo_slug}")
    lines.append(f"  Generated: {datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("=" * 70)
    lines.append(f"\n  Total exposed items: {len(findings)}\n")

    for idx, f in enumerate(findings, 1):
        lines.append(f"\n{'─'*70}")
        lines.append(f"  Finding #{idx}")
        lines.append(f"{'─'*70}")
        lines.append(f"  Hazard Rating:  {f['hazard']}")
        lines.append(f"  Secret Type:    {f['secret_type']}")
        lines.append(f"  Pattern:        {f['pattern']}")
        lines.append(f"  Repository:     {f['repo']}")
        lines.append(f"  Repository URL: {f['repo_url']}")
        lines.append(f"  Raw File URL:   {f['raw_url']}")
        lines.append(f"  File:           {f['file']}")
        lines.append(f"  Line Number:    {f['line']}")
        lines.append(f"  Evidence:")
        lines.append(f"    \"{f['excerpt']}\"")
        lines.append(f"\n  How to Fix:")
        action = {
            "HIGH":    "Rotate/revoke the exposed credential immediately. Remove from repo history via BFG or git-filter-repo. Re-issue a new key. Check CloudTrail / access logs for abuse.",
            "MEDIUM":  "Move credentials to a secrets manager (HashiCorp Vault, AWS Secrets Manager, GitHub Secrets). Rotate the exposed value. Review commits for use.",
            "LOW":     "Remove hard-coded reference from code. Use environment variables or secrets manager.",
        }.get(f['hazard'],
              "Remove the hard-coded secret. Use environment variables or a secrets manager. Rotate/revoke the credential.")
        lines.append(textwrap.indent(action, "    "))
        lines.append(f"\n  Steps to Reproduce (for H1 report):")
        lines.append(f"    1. Visit {f['repo_url']}")
        lines.append(f"    2. Open file: {f['file']}")
        lines.append(f"    3. Check line {f['line']} — expected result: value of type '{f['secret_type']}' is visible")
        lines.append(f"    4. curl {f['raw_url']} — payload on line {f['line']}: {f['excerpt'][:150]}")

    fpath.write_text("\n".join(lines), encoding="utf-8")
    return fpath


def main():
    parser = argparse.ArgumentParser(
        description="GitHub Exposed-Secrets Scanner — disclose responsibly",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
          Examples:
            python scanner.py --orgs cia,fbi,apple
            python scanner.py --repos org/repo1,org/repo2 --output-dir findings/ --report report.txt
            python scanner.py --orgs example corp --github-token ghp_xxxx
        """),
    )
    parser.add_argument("--orgs",        type=str, help="Comma-separated org names")
    parser.add_argument("--repos",       type=str, help="Comma-separated org/repo slugs")
    parser.add_argument("--output-dir",  type=str, default=str(FINDINGS_DIR), help="Findings output dir")
    parser.add_argument("--report",      type=str, default=str(BASE_DIR / "report.txt"), help="Summary report path")
    parser.add_argument("--github-token",      type=str, default=None, help="GitHub PAT (higher rate limits)")
    parser.add_argument("--max-pages",         type=int, default=1,     help="Max pages to fetch per pattern (default 1 = fast scan)")
    parser.add_argument("--max-findings",      type=int, default=10,    help="Max findings per repo across all patterns")
    parser.add_argument("--patterns",    type=str, default=None,
                         help="Comma-sep pattern names or 'all'; omit for 10 critical defaults")
    parser.add_argument("--repos-batch-size", type=int, default=MAX_REPOS_PER_SEARCH,
                         help="Repos combined in one search query (default MAP_PER_SEARCH)")
    parser.add_argument("--pattern-count",    type=int, default=None,
                         help="Use only top-N patterns from patterns.json (default: 72 slow, or --patterns critical)")
    parser.add_argument("--no-color",         action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    global USE_COLOR
    if args.no_color:
        USE_COLOR = False

    patterns = load_patterns()
    print(f"[INFO] Loaded {len(patterns)} secret patterns")
    print(f"[INFO] Patterns: {', '.join(list(patterns.keys())[:5])} ... (+{len(patterns)-5} more)")

    repos = load_repos_and_orgs(args)
    if not repos:
        print("[ERROR] No repos found. Check org names or provide --repos")
        sys.exit(1)
    print(f"[INFO] Scanning {len(repos)} repo(s) with {len(patterns)} patterns\n")

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    headers = make_headers(args.github_token)
    if not args.github_token:
        print("[WARN] No --github-token provided. Search API limited to 10 req/min. Add a PAT for 30 req/min.")
    show_rate_limit(headers)

    all_repo_files   = []
    all_findings     = []
    req_counter      = [0]

    # ── Pattern selection ──────────────────────────────────────────────────
    if args.patterns and args.patterns.lower() != "all":
        sel_patterns = {k: patterns[k] for k in DEFAULT_PATTERNS if k in patterns}
        print(f"[INFO] Scanning with {len(sel_patterns)} key patterns: {list(sel_patterns.keys())[:8]} …")
    elif args.pattern_count:
        top = list(patterns.items())[:args.pattern_count]
        sel_patterns = dict(top)
        print(f"[INFO] Scanning with top {len(sel_patterns)} patterns (--pattern-count={args.pattern_count})")
    else:
        sel_patterns = patterns
        print(f"[INFO] Scanning with ALL {len(sel_patterns)} patterns (full + slow)")

    # ── Multi-repo search batching ─────────────────────────────────────────
    batch_size   = max(1, min(getattr(args, "repos_batch_size", MAX_REPOS_PER_SEARCH), MAX_REPOS_PER_SEARCH))
    repo_batches = [repos[i:i + batch_size] for i in range(0, len(repos), batch_size)]
    total_q = len(repo_batches) * len(sel_patterns)
    est_min = total_q * SLEEP_BETWEEN_SEARCHES / 60
    throttle = SLEEP_BETWEEN_SEARCHES
    print(f"[BATCHES] {len(repos)} repos -> {len(repo_batches)} batches x {batch_size} repos/query"
          f"    {total_q} search requests | ~{est_min:.0f}min @ {throttle}s/q")

    for batch_idx, batch_repos in enumerate(repo_batches):
        batch_label = batch_repos[0]
        print(f"\n[Batch {batch_idx+1}/{len(repo_batches)}] repos: {batch_repos}")
        findings = scan_repo(batch_label, batch_repos, sel_patterns, headers,
                             req_counter, max_pages=args.max_pages, max_findings=args.max_findings)
        if findings:
            # write per-actual-repo file
            by_repo = {}
            for f in findings:
                by_repo.setdefault(f['repo'], []).append(f)
            for rslug, rf in by_repo.items():
                wpath = write_repo_finding_file(rslug, rf, out_dir)
                all_repo_files.append(wpath)
            all_findings.extend(findings)
            print(f"[RESULT] {len(findings)} finding(s) across {len(by_repo)} repo(s) in this batch")
        else:
            print(f"[OK] No secrets in this batch")

    print(f"\n{'='*70}")
    print(f"[DONE] Repos scanned: {len(repos)}")
    print(f"[DONE] Total findings:  {len(all_findings)}")
    print(f"[DONE] Reports written: {len(all_repo_files)}")

    if all_findings:
        write_summary_report(all_findings, args.report)
    else:
        print("[INFO] No secrets found — no summary report written.")


if __name__ == "__main__":
    main()
