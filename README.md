# GitHub Exposed-Secrets Scanner

Scans public GitHub repos via the GitHub Search API for exposed API keys,
credentials, tokens, private keys, and hardcoded secrets. Generates per-repo
findings files and a ready-to-submit bug-bounty report.

## Installation

```bash
pip install requests colorama
cd /root/tools/penetest/github-secret-scanner
```

## Quick Usage

```bash
python scanner.py --orgs cia,fbi,apple,google,netlify --report report.txt
```

## Arguments

| Flag               | Description                                |
|--------------------|--------------------------------------------|
| `--orgs`           | Comma-separated org names (e.g. `cia,fbi`) |
| `--repos`          | Comma-separated org/repo slugs             |
| `--github-token`   | GitHub PAT (30 req/min vs 10 without)      |
| `--output-dir`     | Findings output directory                  |
| `--report`         | Summary report path                        |
| `--no-color`       | Disable ANSI colors                        |

**Examples:**

```bash
# Scan orgs
python scanner.py --orgs cia,fbi,apple

# Specific repos
python scanner.py --repos ridhinva/exploit,facebook/react

# With token
python scanner.py --orgs cia --github-token ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Cron wrapper
./scan_and_report.sh --orgs cia,fbi,apple --github-token ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

## Output

```
findings/
├── cia/
│   └── cia-website.txt
├── fbi/
└── apple/
    └── official-website.txt
report.txt
h1_report_YYYY-MM-DD_HHMM.txt
```

Each `<repo>.txt` contains:
- Hazard rating (HIGH / MEDIUM / LOW)
- Secret type and pattern
- Repository + file URL + line number
- Code excerpt (the actual exposed value)
- How to fix + steps to reproduce

`report.txt` is a cross-org summary. `findings_to_h1_report.py` converts it into a HackerOne-ready report block.

## 72 Built-in Patterns

AWS Access Key ID, AWS Secret Access Key, AWS Session Token, Google API Key,
Google OAuth Client ID, GitHub PAT (ghp_/gho_/ghs_/ghr_), GitHub Fine-Grained PAT,
Slack Token, Slack Webhook, Stripe Live/Test Keys, SendGrid API Key,
Mailgun API Key, Twilio API Key + Account SID, Heroku Token, Cloudflare Token,
Datadog API Key, New Relic License Key, PagerDuty Token, Mailchimp API Key,
Facebook Token, Twitter Bearer + API Key, Generic Bearer Auth, JWT,
Hard-coded password/secret_key/api_key/token, Database URLs (MySQL/Postgres/MongoDB/Redis),
JDBC Connection Strings, Private Keys (RSA/EC/DSA/OpenSSH/SAML),
NPM Token, Netlify Token, Vercel Token, Pip Password, Jenkins Token, Kubernetes
Tokens/Secrets, OAuth Client Secret, Okta Token, Square Tokens, PayPal Braintree,
GitHub Actions Token, e + 50 more.

## H1 Report Generator

```bash
python findings_to_h1_report.py report.txt --output h1_report.txt
python findings_to_h1_report.py report.txt --org cia --hazard HIGH
```

Output is immediately copy-pasteable into HackerOne / Bugcrowd / Intigriti.

## Limitations

- GitHub Code Search API returns at most 1,000 results per query.
- Public repos only (private repos need a PAT with repo scope + the repo must be
  accessible to the token owner).
- Rate-limit: 60 req/hr unauthenticated, 30 req/min authenticated.
- Add `--github-token` for higher limits and access to org repos.

## Responsible Disclosure

Only scan repos you are authorised to test. Report findings privately to the
repo owner or via their bug-bounty program before any public disclosure.
