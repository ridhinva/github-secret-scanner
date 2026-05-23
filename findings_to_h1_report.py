#!/usr/bin/env python3
"""
findings_to_h1_report.py
Converts scanner findings into HackerOne-style report markup ready to submit.

Usage:
  python findings_to_h1_report.py report.txt                   # reads from scanner summary report
  python findings_to_h1_report.py report.txt --output h1_report.txt
  python findings_to_h1_report.py report.txt --org cia          # filter to one org

Output format:
  Title
  Target
  Description
  Steps to Reproduce
  Impact
  Remediation
  [--- separate report per HIGHfinding ---]
"""

import argparse, re, sys
from pathlib import Path
from datetime import datetime

try:
    from colorama import init as _ci, Fore, Style
    _ci()
    C = True
except ImportError:
    C = False

CRITICAL_PARAMS = [
    "aws_access_key_id", "aws_secret_access_key", "stripe_live_key",
    "slack_token", "github_", "google_api_key", "twilio_", "heroku_api_key",
    "private_key", "database_url", "jwt_token", "oauth_client_secret",
    "cloudflare_api", "netlify_auth", "vercel_api_token", "sendgrid_api_key",
    "okta_token", "paypal_", "newrelic_license_key", "pagerduty_",
    "github_actions_token",
]

def parse_summary(report_path):
    text = Path(report_path).read_text(encoding="utf-8")
    findings = []
    current = {}
    for line in text.splitlines():
        m = re.match(r'^\s+\[([A-Z]+)\]\s+(.+)$', line)
        if m:
            if current.get("hazard"):
                findings.append(current)
            current = {"hazard": m.group(1), "secret_type": m.group(2).strip()}
        elif line.strip().startswith("Repo:") and current:
            current["repo"] = line.split(":",1)[1].strip()
        elif line.strip().startswith("File:") and current:
            current["file"] = line.split(":",1)[1].strip()
        elif line.strip().startswith("Line:") and current:
            current["line"] = line.split(":",1)[1].strip()
        elif line.strip().startswith("URL:") and current:
            current["repo_url"] = line.split(":",1)[1].strip()
        elif line.strip().startswith("Evidence:") and current:
            current["evidence"] = line.split(":",1)[1].strip()
    if current.get("hazard"):
        findings.append(current)
    return findings


def build_h1_report(finding):
    repo    = finding.get("repo", "unknown")
    repo_url= finding.get("repo_url", "N/A")
    fpath   = finding.get("file", "N/A")
    hazard  = finding.get("hazard", "MEDIUM")
    stype   = finding.get("secret_type", "Secret")
    evidence= finding.get("evidence", "N/A")
    line    = finding.get("line","N/A")

    impact_map = {
        "HIGH":    "An attacker can take over accounts, make unauthorized API requests, exfiltrate user data, pivot to cloud infrastructure, or escalate access using this exposed credential.",
        "MEDIUM":  "Token/key exposure creates risk of unauthorized access to related services. Impact depends on the scope of the credential.",
        "LOW":     "Exposing configuration data increases attack surface. Should be rotated to best-practice standards.",
    }
    impact = impact_map.get(hazard, impact_map["MEDIUM"])

    title_map = {
        "aws_access_key_id":       f"Exposed AWS Access Key ID in {repo} [{hazard}]",
        "slack_token":             f"Exposed Slack Token in {repo} [{hazard}]",
        "github_":                 f"Exposed GitHub Token in {repo} [{hazard}]",
        "private_key":             f"Hard-coded Private Key in {repo} [{hazard}]",
        "database_url":            f"Hard-coded Database Credentials in {repo} [{hazard}]",
        "jwt_token":               f"Hard-coded JWT in {repo} [{hazard}]",
        "google_api_key":          f"Exposed Google API Key in {repo} [{hazard}]",
        "stripe_live_key":         f"Exposed Stripe Live Key in {repo} [{hazard}]",
    }
    title = title_map.get(stype, f"Exposed {stype} in {repo} [{hazard}]")
    for k,v in title_map.items():
        if k in stype.lower():
            title = v
            break

    return f"""\
════════════════════════════════════════════════════════════════════
H1 REPORT — {title}
════════════════════════════════════════════════════════════════════

TITLE:
  {title}

TARGET:
  Organization: {repo.split("/",1)[0] if '/' in repo else repo}
  Repository:   {repo}
  Repository URL: {repo_url}

DESCRIPTION:
  A {hazard.lower()}-severity secret ({stype}) was found hard-coded in the public
  source code of the {repo} repository at file `{fpath}` (line {line}).

  The credential is fully visible to any GitHub user, crawler, or automated
  secret-scanning tool without any authentication required.

STEPS TO REPRODUCE:
  1. Go to {repo_url}
  2. Navigate to: {fpath}
  3. Locate line {line} — the value '{stype}' is visible in plain text
  4. Alternatively, curl the raw file:
       curl {f'<raw_url>'}
       # Look for the credential on/around line {line}

  5. Proof of concept / affected line:
     {evidence}

EXPECTED RESULT:
  The credential should not be present in source code. Secrets should be loaded
  from a secrets manager (HashiCorp Vault, AWS Secrets Manager, GitHub Secrets,
  environment variables, etc.).

ACTUAL RESULT:
  The {stype} is hard-coded as a literal string in the public source tree.

IMPACT:
  {impact}

REMEDIATION:
  1. {hazard == 'HIGH' and 'IMMEDIATELY revoke / rotate the exposed credential.' or 'Rotate the exposed credential.'}
  2. Remove the hard-coded secret from the repository source.
  3. Purge it from git history using BFG Repo-Cleaner or git filter-repo:
       bfg --delete-files <SECRET_89d58b5f>.json  {repo_url}
  4. Replace with environment variables or a secrets manager.
  5. Rotate / regenerate any token derived from the same shared secret.
  6. Audit access logs for unexpected usage.
  7. Use GitHub Security Advisories secret scanning to prevent future exposure.

REFERENCES:
  • GitHub Secret Scanning: https://docs.github.com/en/code-security/secret-scanning
  • OWASP Top 10 A02:2021 — Cryptographic Failures
  • Git history sanitizing: git-filter-repo / BFG Repo-Cleaner

─────────────────────────────────────────────────────────────────────
REPORT GENERATED: {datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}
SCANNER: GitHub Exposed-Secrets Scanner v 1.1
════════════════════════════════════════════════════════════════════

"""


def main():
    ap = argparse.ArgumentParser(description="Convert scanner findings → HackerOne-style report")
    ap.add_argument("report", help="Path to scanner report.txt")
    ap.add_argument("--output", default=None, help="Output file (default: stdout or auto-name)")
    ap.add_argument("--org",    default=None, help="Filter findings to specific org")
    ap.add_argument("--hazard", default=None, help="Filter by hazard: HIGH/MEDIUM/LOW")
    args = ap.parse_args()

    findings = parse_summary(args.report)

    if args.org:
        findings = [f for f in findings if f.get("repo","").lower().startswith(args.org.lower()+"/")]
    if args.hazard:
        findings = [f for f in findings if f.get("hazard","").upper() == args.hazard.upper()]

    if not findings:
        print("[INFO] No findings match the filter.")
        return

    reports = []
    for f in findings:
        reports.append(build_h1_report(f))
    combined = "\n\n".join(reports) + f"\n\n=== Generated {len(reports)} report block(s) ===\n"

    if args.output:
        Path(args.output).write_text(combined, encoding="utf-8")
        print(f"[SAVED] H1 report → {args.output}")
    else:
        print(combined)

if __name__ == "__main__":
    main()
