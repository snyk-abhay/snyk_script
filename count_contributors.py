#!/usr/bin/env python3
"""
Count unique contributing developers (Snyk-style) on GitHub / GitHub Enterprise.

Definition used (mirrors Snyk):
  - Commits on the DEFAULT branch
  - In the last N days (default 90)
  - Private repos only (use --include-public to add public ones)
  - Unique by commit author email (case-insensitive)
  - Bots and *noreply.github.com emails excluded (use --keep-noreply to keep them)

No scanning, no dependencies (standard library only). Python 3.8+.

Usage:
  export GH_TOKEN=ghp_xxx
  python3 count_contributors.py --orgs MyOrg
  python3 count_contributors.py --orgs OrgA OrgB --days 90
  python3 count_contributors.py --repos MyOrg/repo1 MyOrg/repo2
  python3 count_contributors.py --repos-file repos.txt        # one owner/repo per line
  python3 count_contributors.py --orgs MyOrg --ghe-url https://github.mycorp.com

Full-scope scans:
  python3 count_contributors.py --all-orgs                  # every org you're a member of
  python3 count_contributors.py --everything                # every repo the token can access
  python3 count_contributors.py --enterprise my-ent-slug    # every org in the enterprise account
  python3 count_contributors.py --all-server-orgs --ghe-url https://github.mycorp.com   # whole GHE server
  (flags can be combined; repos are de-duplicated)

Outputs:
  contributors_summary.csv   one row per repo (contributor count)
  contributors_list.csv      one row per unique developer (email, name, #commits, repos)
"""

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

BOT_PATTERN = re.compile(r"(\[bot\]|-bot@|bot@|dependabot|renovate|snyk-bot|github-actions|jenkins|noreply@github\.com)", re.I)
NOREPLY_PATTERN = re.compile(r"noreply\.github\.com$", re.I)


class GitHub:
    def __init__(self, token, base_url):
        self.token = token
        self.base = base_url.rstrip("/")

    def _request(self, url, payload=None):
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "contributor-counter",
            "Content-Type": "application/json",
        }, data=json.dumps(payload).encode() if payload is not None else None)
        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    body = resp.read().decode()
                    return (json.loads(body) if body else None), resp.headers
            except urllib.error.HTTPError as e:
                msg = e.read().decode(errors="ignore")
                if e.code in (403, 429) and ("rate limit" in msg.lower() or e.headers.get("Retry-After")):
                    reset = e.headers.get("X-RateLimit-Reset")
                    wait = int(e.headers.get("Retry-After") or (max(int(reset) - int(time.time()), 1) if reset else 60))
                    print(f"  Rate limited. Waiting {wait}s...", file=sys.stderr)
                    time.sleep(min(wait, 900))
                    continue
                if e.code == 403 and "SAML" in msg:
                    raise SystemExit("ERROR: Token not authorized for SAML SSO. GitHub > Settings > Developer settings > "
                                     "Tokens > Configure SSO > Authorize your org.")
                if e.code == 401:
                    raise SystemExit("ERROR: Bad or expired token (401).")
                if e.code == 409:   # empty repository
                    return [], {}
                if e.code == 404:
                    return None, {}
                if e.code >= 500 and attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise SystemExit(f"ERROR {e.code} on {url}: {msg[:300]}")
            except urllib.error.URLError as e:
                if attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise SystemExit(f"ERROR: cannot reach {url}: {e}")
        raise SystemExit(f"ERROR: gave up on {url}")

    def paginate(self, path, params=None):
        params = dict(params or {}, per_page=100)
        url = f"{self.base}{path}?{urllib.parse.urlencode(params)}"
        while url:
            data, headers = self._request(url)
            if not data:
                return
            for item in data:
                yield item
            url = None
            link = headers.get("Link", "") if headers else ""
            for part in link.split(","):
                if 'rel="next"' in part:
                    url = part[part.find("<") + 1:part.find(">")]

    def get(self, path):
        data, _ = self._request(f"{self.base}{path}")
        return data

    def graphql(self, query, variables):
        url = self.base.replace("/api/v3", "/api/graphql") if self.base.endswith("/api/v3") else f"{self.base}/graphql"
        data, _ = self._request(url, {"query": query, "variables": variables})
        if data and data.get("errors"):
            raise SystemExit(f"GraphQL error: {data['errors'][0].get('message')}")
        return (data or {}).get("data") or {}


def enterprise_orgs(gh, slug):
    """All orgs in a GitHub Enterprise Cloud/Server enterprise account (needs read:enterprise scope)."""
    q = """query($slug:String!,$after:String){ enterprise(slug:$slug){ organizations(first:100, after:$after){
             nodes{ login } pageInfo{ hasNextPage endCursor } } } }"""
    orgs, after = [], None
    while True:
        ent = gh.graphql(q, {"slug": slug, "after": after}).get("enterprise")
        if not ent:
            raise SystemExit(f"Enterprise '{slug}' not found or token lacks 'read:enterprise' / enterprise membership.")
        page = ent["organizations"]
        orgs += [n["login"] for n in page["nodes"]]
        if not page["pageInfo"]["hasNextPage"]:
            return orgs
        after = page["pageInfo"]["endCursor"]


def resolve_orgs(gh, args):
    orgs = list(args.orgs or [])
    if args.all_orgs:
        mine = [o["login"] for o in gh.paginate("/user/orgs")]
        print(f"--all-orgs: {len(mine)} orgs visible to token")
        orgs += mine
    if args.enterprise:
        ent = enterprise_orgs(gh, args.enterprise)
        print(f"--enterprise {args.enterprise}: {len(ent)} orgs")
        orgs += ent
    if args.all_server_orgs:
        if not args.ghe_url:
            raise SystemExit("--all-server-orgs only works with --ghe-url (GitHub Enterprise Server).")
        srv = [o["login"] for o in gh.paginate("/organizations")]
        print(f"--all-server-orgs: {len(srv)} orgs on the server")
        orgs += srv
    return list(dict.fromkeys(orgs))   # dedupe, keep order


def list_repos(gh, args):
    repos = []
    if args.everything:
        # Every repo the token can access: own, collaborator, and all org memberships
        print("--everything: listing every repo the token can access...")
        repos.extend(gh.paginate("/user/repos", {"affiliation": "owner,collaborator,organization_member",
                                                 "visibility": "all"}))
    if args.user_repos:
        repos.extend(gh.paginate("/user/repos", {"affiliation": "owner", "visibility": "all"}))
    if args.repos or args.repos_file:
        names = list(args.repos or [])
        if args.repos_file:
            with open(args.repos_file) as f:
                names += [l.strip() for l in f if l.strip() and not l.startswith("#")]
        for full in names:
            r = gh.get(f"/repos/{full}")
            if r is None:
                print(f"  WARN: {full} not found or no access", file=sys.stderr)
                continue
            repos.append(r)

    orgs = resolve_orgs(gh, args)
    nothing_chosen = not (orgs or repos or args.everything or args.user_repos or args.repos or args.repos_file)
    if nothing_chosen:
        orgs = [o["login"] for o in gh.paginate("/user/orgs")]
        print(f"No scope given, defaulting to all orgs visible to token: {orgs or 'NONE'}")
        if not orgs:
            raise SystemExit("Token sees no orgs. Check 'read:org' scope and SSO authorization, "
                             "or use --everything / --user-repos.")
    for org in orgs:
        found = list(gh.paginate(f"/orgs/{org}/repos", {"type": "all"}))
        print(f"  org {org}: {len(found)} repos")
        if not found:
            print(f"  WARN: 0 repos visible in org '{org}' (check 'repo' scope / SSO / membership)", file=sys.stderr)
        repos.extend(found)

    seen, out = set(), []
    for r in repos:
        if r["full_name"] in seen:
            continue
        seen.add(r["full_name"])
        if r.get("archived") and not args.include_archived:
            continue
        if not r.get("private") and not args.include_public:
            continue
        out.append(r)
    return out


def main():
    p = argparse.ArgumentParser(description="Count unique contributing developers (last N days, default branch).")
    p.add_argument("--orgs", nargs="*", help="GitHub org names")
    p.add_argument("--repos", nargs="*", help="owner/repo entries")
    p.add_argument("--repos-file", help="File with owner/repo per line")
    p.add_argument("--all-orgs", action="store_true", help="All orgs the token user is a member of")
    p.add_argument("--everything", action="store_true",
                   help="Every repo the token can access (own + collaborator + all orgs)")
    p.add_argument("--user-repos", action="store_true", help="Include repos owned by the token user")
    p.add_argument("--enterprise", help="Enterprise slug: scan ALL orgs in the enterprise (needs read:enterprise)")
    p.add_argument("--all-server-orgs", action="store_true",
                   help="GHE Server only: ALL orgs on the instance (run as site admin to see every org)")
    p.add_argument("--days", type=int, default=90)
    p.add_argument("--ghe-url", help="GitHub Enterprise Server URL, e.g. https://github.mycorp.com")
    p.add_argument("--include-public", action="store_true", help="Also count public repos")
    p.add_argument("--include-archived", action="store_true", help="Also count archived repos")
    p.add_argument("--keep-noreply", action="store_true", help="Keep *noreply.github.com emails")
    p.add_argument("--exclude-file", help="File with emails to exclude (one per line)")
    p.add_argument("--out-dir", default=".")
    args = p.parse_args()

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("Set GH_TOKEN env var first:  export GH_TOKEN=ghp_xxx")

    base = f"{args.ghe_url.rstrip('/')}/api/v3" if args.ghe_url else "https://api.github.com"
    gh = GitHub(token, base)

    me = gh.get("/user")
    print(f"Authenticated as: {me.get('login') if me else 'unknown'}")

    excluded = set()
    if args.exclude_file:
        with open(args.exclude_file) as f:
            excluded = {l.strip().lower() for l in f if l.strip()}

    since = (datetime.now(timezone.utc) - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    repos = list_repos(gh, args)
    print(f"Repos in scope: {len(repos)}  |  Window: last {args.days} days (since {since})\n")

    devs = {}                       # email -> {name, commits, repos}
    repo_rows = []
    skipped = defaultdict(int)

    for i, r in enumerate(repos, 1):
        full, branch = r["full_name"], r.get("default_branch") or "main"
        repo_devs = set()
        commits = 0
        for c in gh.paginate(f"/repos/{full}/commits", {"sha": branch, "since": since}):
            author = (c.get("commit") or {}).get("author") or {}
            email = (author.get("email") or "").strip().lower()
            name = author.get("name") or ""
            login = (c.get("author") or {}).get("login") or ""
            if not email:
                skipped["no_email"] += 1
                continue
            if BOT_PATTERN.search(email) or BOT_PATTERN.search(login) or login.endswith("[bot]"):
                skipped["bot"] += 1
                continue
            if not args.keep_noreply and NOREPLY_PATTERN.search(email):
                skipped["noreply"] += 1
                continue
            if email in excluded:
                skipped["excluded"] += 1
                continue
            commits += 1
            repo_devs.add(email)
            d = devs.setdefault(email, {"name": name, "login": login, "commits": 0, "repos": set()})
            d["commits"] += 1
            d["repos"].add(full)
            if login and not d["login"]:
                d["login"] = login
        repo_rows.append((full, "private" if r.get("private") else "public", branch, len(repo_devs), commits))
        print(f"[{i}/{len(repos)}] {full} ({branch}): {len(repo_devs)} contributors, {commits} commits")

    os.makedirs(args.out_dir, exist_ok=True)
    summary_path = os.path.join(args.out_dir, "contributors_summary.csv")
    list_path = os.path.join(args.out_dir, "contributors_list.csv")

    with open(summary_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["repo", "visibility", "default_branch", "unique_contributors", "commits_counted"])
        for row in sorted(repo_rows, key=lambda x: -x[3]):
            w.writerow(row)

    with open(list_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["email", "name", "github_login", "commits", "repo_count", "repos"])
        for email, d in sorted(devs.items(), key=lambda x: -x[1]["commits"]):
            w.writerow([email, d["name"], d["login"], d["commits"], len(d["repos"]), ";".join(sorted(d["repos"]))])

    active = sum(1 for r in repo_rows if r[3] > 0)
    print("\n==================== SUMMARY ====================")
    print(f"Repos scanned                : {len(repo_rows)}")
    print(f"Repos with commits in window : {active}")
    print(f"UNIQUE CONTRIBUTING DEVS     : {len(devs)}")
    print(f"Skipped commits              : {dict(skipped) or 0}")
    print(f"Per-repo report              : {summary_path}")
    print(f"Developer list               : {list_path}")
    print("=================================================")


if __name__ == "__main__":
    main()
