#!/usr/bin/env python3
"""enumerate_org_repos.py — enumerate all public repos for orgs in TARGET_ORGS.json and save to repos_batch_N.txt"""
import json, os, sys, requests, time
from pathlib import Path

TOKEN    = os.environ.get("GITHUB_TOKEN", "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
SC_DIR   = Path('/root/tools/pentest/github-secret-scanner')
ORG_FILE = SC_DIR / 'TARGET_ORGS.json'
BATCH_DIR = SC_DIR / 'batches'
BATCH_DIR.mkdir(exist_ok=True)

h = {"Authorization": f"token {TOKEN}", "User-Agent": "GitHub-Secret-Scanner/1.1"}

all_orgs = json.loads(ORG_FILE.read_text())
print(f"Loaded {len(all_orgs)} orgs: {list(all_orgs.keys())}")

# Order: P1 first, then P2 by ascending max_repos to maximise fast wins
p1 = {k: v for k, v in all_orgs.items() if v.get("priority") == 1}
p2 = sorted({k: v for k, v in all_orgs.items() if v.get("priority") != 1}.items(),
            key=lambda x: x[1].get("max_repos", 999))
ordered = {**p1, **dict(p2)}

batch_size  = 500   # repos per batch file
all_repos   = []
repo_counts = {}

for org, meta in ordered.items():
    cap = meta.get("max_repos", 100)
    page = 1
    org_repos = []
    while True:
        try:
            r = requests.get(
                f"https://api.github.com/orgs/{org}/repos",
                headers=h,
                params={"per_page": 100, "page": page, "type": "public", "sort": "updated", "direction": "desc"},
                timeout=15,
            )
            if r.status_code == 404:
                print(f"  [WARN] Org '{org}' not found (404)")
                break
            r.raise_for_status()
            batch = r.json()
            if not batch:
                break
            names = [f"{org}/{b['name']}" for b in batch]
            org_repos.extend(names[:cap - len(org_repos)])
            page += 1
            if len(org_repos) >= cap or len(batch) < 100:
                break
        except Exception as e:
            print(f"  [ERR] {org}: {e}")
            break
    repo_counts[org] = len(org_repos)
    all_repos.extend(org_repos)
    print(f"  [{org}] {len(org_repos)} repos")

print(f"\nTotal repos enumerated: {len(all_repos)}")

# Save master list
(SC_DIR / 'all_repos.txt').write_text('\n'.join(sorted(all_repos)), encoding='utf-8')
print(f"Saved master list → {SC_DIR / 'all_repos.txt'}")

# Split into batches
batches = []
for i in range(0, len(all_repos), batch_size):
    batch = all_repos[i:i+batch_size]
    bn = BATCH_DIR / f"batch_{i//batch_size+1:03d}.txt"
    bn.write_text('\n'.join(batch), encoding='utf-8')
    batches.append(bn)
    print(f"  batch_{i//batch_size+1:03d}.txt → {len(batch)} repos")

print(f"\nWrote {len(batches)} batch files to {BATCH_DIR}")
