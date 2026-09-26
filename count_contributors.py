#!/usr/bin/env python3
"""
Python port of snyk-tech-services/snyk-scm-contributors-count (GitHub + GitHub Enterprise).
https://github.com/snyk-tech-services/snyk-scm-contributors-count

Same logic as the official tool:
  * Repo discovery
      --repo + single --orgs  -> just that repo
      no --orgs               -> all orgs of the token user (/user/orgs), then all their repos
                                 (GHE with --fetchAllOrgs -> every org on the server via /organizations)
      --orgs a,b              -> all repos of those orgs (/orgs/{org}/repos)
    Public AND private repos, archived included (no filtering, same as upstream).
  * Commits: GET /repos/{owner}/{repo}/commits?per_page=100&since=<90 days ago>
    (no branch param -> the repo's DEFAULT branch)
  * Contributors keyed by commit author NAME; same name + different email -> "name(duplicate)"
  * Skipped: emails ending in "@users.noreply.github.com" and "snyk-bot@snyk.io"
  * Then de-duplicated by EMAIL, exclusion file applied (one email per line), summary printed.
  * 800 ms between API calls, 1 concurrent request; HTTP 429 -> wait 3 min and retry;
    HTTP 409 (empty repo) -> no commits.

Standard library only. Python 3.8+.

Usage (same flags as the npm tool):
  python3 count_contributors.py github --token <TOKEN>
  python3 count_contributors.py github --token <TOKEN> --orgs OrgA,OrgB
  python3 count_contributors.py github --token <TOKEN> --orgs OrgA --repo my-repo
  python3 count_contributors.py github --token <TOKEN> --exclusionFilePath ./snyk.exclude --json
  python3 count_contributors.py github-enterprise --token <TOKEN> --url https://ghe.company.com
  python3 count_contributors.py github-enterprise --token <TOKEN> --url https://ghe.company.com --fetchAllOrgs

  --token can be omitted if GH_TOKEN / GITHUB_TOKEN is exported.

Snyk coverage mode (--snyk, needs SNYK_TOKEN):
  export GH_TOKEN=<github token>  SNYK_TOKEN=<snyk token>
  python3 count_contributors.py github --orgs induscope --snyk
  python3 count_contributors.py github --orgs induscope --snyk --snykGroupId <group-id> --outputDir ./report
  python3 count_contributors.py github --orgs induscope --snyk --json

  Answers, for the GitHub scope the token can see:
    1. How many repos are scanned (monitored) in Snyk
    2. Contributing developers (last 90 days) on those Snyk-scanned repos
    3. How many repos are NOT scanned / not tested by Snyk (and which are active)
    4. Contributing developers across ALL repos in GitHub, and how many extra
       developers would be added if the unscanned repos were onboarded
  A repo counts as "scanned" when any Snyk org visible to SNYK_TOKEN has a target for it:
  SCM-integration targets matched by "owner/repo", CLI/CI targets matched by remote URL.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

# ----------------------------------------------------------------------------- logging

DEBUG = "snyk" in (os.environ.get("DEBUG") or "")
USE_COLOR = sys.stdout.isatty()
SCM = "Github"          # "Github Enterprise" for the github-enterprise command
ERR_OUT = sys.stdout     # upstream prints failures to stdout; --snyk --json redirects to stderr


def debug(msg):
    if DEBUG:
        print(f"  snyk:github-count {msg}", file=sys.stderr)


def color(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def yellow(t):
    return color(t, "93")


def blue(t):
    return color(t, "94")


class Spinner:
    """Minimal stand-in for `ora`: prints '✔ step' to stderr unless quiet."""

    def __init__(self, quiet):
        self.quiet = quiet

    def succeed(self, text):
        if not self.quiet:
            print(f"{color('✔', '32')} {text}", file=sys.stderr)


# ----------------------------------------------------------------------------- HTTP (fetchAllPages)

MIN_TIME = 0.8          # Bottleneck minTime: 800 ms between requests
_last_call = [0.0]


def _raw_get(url, token):
    wait = MIN_TIME - (time.time() - _last_call[0])
    if wait > 0:
        time.sleep(wait)
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "User-Agent": "snyk-scm-contributors-count-py",
    })
    attempt = 0
    while True:
        try:
            _last_call[0] = time.time()
            resp = urllib.request.urlopen(req, timeout=60)
            return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            _last_call[0] = time.time()
            return e.code, e.headers, e.read()
        except urllib.error.URLError as e:
            # Bottleneck "failed" handler: retry once after 25 ms
            if attempt == 0:
                print(f"Job failed: {e}\nRetrying job in 25ms!", file=sys.stderr)
                attempt += 1
                time.sleep(0.025)
                continue
            raise


def fetch_all_pages(url, token, item_name=""):
    values = []
    page = 1
    while True:
        debug(f"Fetching page {page} for {item_name}")
        status, headers, body = _raw_get(url, token)
        if status >= 400:
            if status == 429:
                debug(f"Failed to fetch page: {url}, Response Status: 429 Too many requests. "
                      f"Waiting for 3 minutes before resuming")
                time.sleep(180)
                debug(f"Retrying to fetch page: {url}")
                status, headers, body = _raw_get(url, token)
            elif status == 409:
                return []
            else:
                debug(f"Failed to fetch page: {url}, Response Status: {status}")
        try:
            data = json.loads(body.decode() or "null")
        except ValueError:
            data = None
        # JS: values = values.concat(apiResponse)  -> arrays spread, objects appended as one item
        if isinstance(data, list):
            values.extend(data)
        elif data is not None:
            values.append(data)
        link = headers.get("link") if headers else None
        if link and 'rel="next"' in link:
            nxt = next((p for p in link.split(",") if 'rel="next"' in p), None)
            if nxt:
                url = nxt.split(";")[0].replace("<", "").replace(">", "").strip()
                if "https" not in url:
                    url = url.replace("http", "https")
        else:
            break
        page += 1
    return values


# ----------------------------------------------------------------------------- GitHub logic

def fetch_orgs(url, token, label):
    org_list = []
    try:
        for org in fetch_all_pages(url, token, label):
            if isinstance(org, dict) and org.get("login"):
                org_list.append(org["login"])
    except Exception as err:
        debug(f"Failed to retrieve project list from {SCM}.\n{err}")
        print(f"Failed to retrieve project list from {SCM}. Try running with `DEBUG=snyk* snyk-contributor`", file=ERR_OUT)
    return org_list


def fetch_repos_for_orgs(api, token, orgs):
    repo_list = []
    try:
        for org in orgs:
            repos = fetch_all_pages(f"{api}orgs/{org}/repos?per_page=100&sort=full_name", token, org)
            if not any(isinstance(r, dict) and r.get("name") for r in repos):
                # Not an org (404) -> maybe a USER account. Extension beyond upstream (which returns 0 here).
                me = fetch_all_pages(f"{api}user", token, "user")
                login = me[0].get("login") if me and isinstance(me[0], dict) else None
                if login and login.lower() == org.lower():
                    # the token owner: include private repos they own
                    user_repos = fetch_all_pages(
                        f"{api}user/repos?per_page=100&affiliation=owner&sort=full_name", token, org)
                else:
                    user_repos = fetch_all_pages(
                        f"{api}users/{org}/repos?per_page=100&type=owner&sort=full_name", token, org)
                if any(isinstance(r, dict) and r.get("name") for r in user_repos):
                    debug(f"'{org}' is a user account, not an org - counting its own repos")
                    print(f"Note: '{org}' is a GitHub user account, not an organization - "
                          f"counting repos owned by that user", file=sys.stderr)
                    repos = user_repos
            for r in repos:
                if not isinstance(r, dict):
                    continue
                name, owner = r.get("name"), (r.get("owner") or {}).get("login")
                if name and owner:
                    repo_list.append({"name": name, "owner": owner, "private": r.get("private"),
                                      "default_branch": r.get("default_branch"),
                                      "archived": r.get("archived")})
    except Exception as err:
        debug(f"Failed to retrieve repo list from {SCM}.\n{err}")
        print(f"Failed to retrieve repo list from {SCM}. Try running with `DEBUG=snyk* snyk-contributor`", file=ERR_OUT)
    return repo_list


def change_duplicate_author_names(name, email, cmap):
    for username, contributor in cmap.items():
        if username == name and email != contributor["email"]:
            return f"{name}(duplicate)"
    return name


# ----------------------------------------------------------------------------- branch selection
# --branch default  -> repo's default branch (upstream behaviour: no `sha` param)      [DEFAULT]
# --branch latest   -> branch whose head commit is the most recent (GraphQL, REST fallback)
# --branch <name>   -> that branch when it exists, otherwise the default branch

BRANCH_MODE = "default"


def _graphql(api, token, query, variables):
    url = api.replace("/api/v3/", "/api/graphql") if api.endswith("/api/v3/") else api + "graphql"
    wait = MIN_TIME - (time.time() - _last_call[0])
    if wait > 0:
        time.sleep(wait)
    req = urllib.request.Request(url, data=json.dumps({"query": query, "variables": variables}).encode(),
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                          "User-Agent": "snyk-scm-contributors-count-py"})
    try:
        _last_call[0] = time.time()
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode() or "{}")
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError) as err:
        debug(f"GraphQL failed: {err}")
        return None
    if body.get("errors"):
        debug(f"GraphQL errors: {body['errors']}")
        return None
    return body.get("data")


LATEST_BRANCH_QUERY = """
query($o:String!,$n:String!){ repository(owner:$o,name:$n){
  defaultBranchRef{ name }
  refs(refPrefix:"refs/heads/", first:1, orderBy:{field:TAG_COMMIT_DATE, direction:DESC}){
    nodes{ name target{ ... on Commit{ committedDate } } } } } }"""


def _latest_branch_rest(api, token, repo):
    """Fallback: read each branch's head commit date (capped at 100 branches)."""
    base = f"{api}repos/{repo['owner']}/{repo['name']}"
    branches = [b for b in fetch_all_pages(f"{base}/branches?per_page=100", token, "branches")
                if isinstance(b, dict) and b.get("name")][:100]
    best, best_date = None, ""
    for b in branches:
        info = fetch_all_pages(f"{base}/branches/{urllib.parse.quote(b['name'], safe='')}", token, b["name"])
        info = info[0] if info and isinstance(info[0], dict) else {}
        date = (((info.get("commit") or {}).get("commit") or {}).get("committer") or {}).get("date") or ""
        if date > best_date:
            best, best_date = b["name"], date
    return best


def resolve_branch(api, token, repo):
    """Returns the branch name to scan, or None to use the default branch (no sha param)."""
    if BRANCH_MODE == "default":
        return None
    base = f"{api}repos/{repo['owner']}/{repo['name']}"
    if BRANCH_MODE != "latest":                          # explicit branch name
        found = fetch_all_pages(f"{base}/branches/{urllib.parse.quote(BRANCH_MODE, safe='')}", token, "branch")
        if found and isinstance(found[0], dict) and found[0].get("name"):
            return BRANCH_MODE
        debug(f"Branch '{BRANCH_MODE}' not found in {repo['owner']}/{repo['name']}, using default branch")
        return None
    data = _graphql(api, token, LATEST_BRANCH_QUERY, {"o": repo["owner"], "n": repo["name"]})
    repo_data = (data or {}).get("repository")
    if repo_data is not None:
        nodes = (repo_data.get("refs") or {}).get("nodes") or []
        if repo_data.get("defaultBranchRef"):
            repo.setdefault("default_branch", repo_data["defaultBranchRef"]["name"])
        return nodes[0]["name"] if nodes else None
    return _latest_branch_rest(api, token, repo)


def fetch_commits_for_repo(api, token, repo, since):
    """Fetch commits since `since` on the selected branch (default branch unless --branch).
    Stops at the first invalid item (error payload), printing the same message the upstream
    tool prints when its per-repo loop throws."""
    debug(f"Fetching single repo contributor from Github. Owner/Org: {repo['owner']} - Repo: {repo['name']}")
    try:
        branch = resolve_branch(api, token, repo)
        repo["scanned_branch"] = branch or repo.get("default_branch") or "(default)"
        sha = f"&sha={urllib.parse.quote(branch, safe='')}" if branch else ""
        debug(f"Branch used for {repo['owner']}/{repo['name']}: {repo['scanned_branch']}")
        commits = fetch_all_pages(
            f"{api}repos/{repo['owner']}/{repo['name']}/commits?per_page=100&since={since}{sha}", token, repo["name"])
    except Exception as err:
        commits, bad = [], err
    else:
        bad = None
        for i, c in enumerate(commits):
            if not (isinstance(c, dict) and isinstance(c.get("commit"), dict)
                    and isinstance(c["commit"].get("author"), dict)):
                bad = f"invalid commit payload: {str(c)[:200]}"
                commits = commits[:i]
                break
    if bad is not None:
        debug(f"Failed to retrieve commits from {SCM}.\n{bad}")
        print(f"Failed to retrieve commits from {SCM}. Try running with `DEBUG=snyk* snyk-contributor`", file=ERR_OUT)
    return commits


def aggregate_repo_contributors(repo, commits, cmap):
    """Upstream per-commit contributor logic (fetchGithubContributorsForRepo)."""
    if True:
        visibility = "Private" if repo.get("private") else "Public"
        repo_str = f"{repo['owner']}/{repo['name']}({visibility})"
        for commit in commits:
            author = commit["commit"]["author"]
            name = author.get("name")
            email = author.get("email") or ""
            contributions = 1
            repos_contributed = [repo_str]

            if name in cmap or email in cmap:
                by_email, by_name = cmap.get(email), cmap.get(name)
                if by_email and by_email["contributionsCount"]:
                    contributions = by_email["contributionsCount"]
                else:
                    contributions = (by_name or {}).get("contributionsCount") or 0
                contributions += 1
                # NOTE: shares the same list object, exactly like the JS version
                if by_email is not None and by_email.get("reposContributedTo") is not None:
                    repos_contributed = by_email["reposContributedTo"]
                elif by_name is not None and by_name.get("reposContributedTo") is not None:
                    repos_contributed = by_name["reposContributedTo"]
                else:
                    repos_contributed = []
                if repo_str not in repos_contributed:
                    repos_contributed.append(repo_str)

            key = change_duplicate_author_names(name, email, cmap)
            if not is_skipped_email(email):
                cmap[key] = {"email": email, "contributionsCount": contributions,
                             "reposContributedTo": repos_contributed}


def is_skipped_email(email):
    return email.endswith("@users.noreply.github.com") or email == "snyk-bot@snyk.io"


def build_contributor_map(repo_list, commits_cache):
    """Run the upstream aggregation over a subset of repos, then sort like `new Map([...].sort())`."""
    cmap = {}
    for r in repo_list:
        aggregate_repo_contributors(r, commits_cache.get(repo_key(r), []), cmap)
    return dict(sorted(cmap.items(), key=lambda kv: f"{kv[0]},[object Object]"))


def repo_key(r):
    return f"{r['owner']}/{r['name']}".lower()


def fetch_github_repos_and_commits(api, token, orgs, repo, since, fetch_all_orgs=False):
    """Returns (repo_list, commits_cache). Same repo discovery as upstream fetchGithubContributors."""
    repo_list, commits_cache = [], {}
    try:
        if repo and (not orgs or len(orgs) > 1):
            print("You must provide a single org name for single repo counting")
            sys.exit(1)
        elif repo and orgs:
            debug("Counting contributors for single repo")
            repo_list.append({"name": repo, "owner": orgs[0]})       # no 'private' -> labelled Public (upstream quirk)
        elif not orgs:
            url = f"{api}organizations?per_page=100" if fetch_all_orgs else f"{api}user/orgs?per_page=100"
            orgs = fetch_orgs(url, token, "Orgs")
            if len(orgs) < 1:
                print("Did not find any Orgs related to the user, please try to append one/few org/s "
                      "to the command with the orgs flag and try again")
            debug(f"Found {len(orgs)} Orgs")
            repo_list += fetch_repos_for_orgs(api, token, orgs)
        else:
            repo_list += fetch_repos_for_orgs(api, token, orgs)
        debug(f"Found {len(repo_list)} Repos")
        for i, r in enumerate(repo_list, 1):
            debug(f"[{i}/{len(repo_list)}] {r['owner']}/{r['name']}")
            commits_cache[repo_key(r)] = fetch_commits_for_repo(api, token, r, since)
    except SystemExit:
        raise
    except Exception as err:
        debug(f"Failed to retrieve contributors from {SCM}.\n{err}")
        print(f"Failed to retrieve contributors from {SCM}. Try running with `DEBUG=snyk* snyk-contributor`", file=ERR_OUT)
    return repo_list, commits_cache


# ----------------------------------------------------------------------------- Snyk logic
# Mirrors upstream src/lib/snyk/index.ts (retrieveMonitoredRepos): list every Snyk org the
# SNYK_TOKEN can see, list each org's targets, and treat a GitHub repo as "monitored/scanned
# by Snyk" when a target matches it (SCM-integration targets by name, CLI/CI targets by
# remote URL on the same host).

SNYK_API_VERSION = "2024-10-15"


def snyk_get_all(base, token, path):
    """GET a Snyk REST collection, following links.next. Returns list of `data` items."""
    items = []
    url = f"{base}/rest{path}"
    while url:
        req = urllib.request.Request(url, headers={
            "Authorization": f"token {token}", "Accept": "application/vnd.api+json",
            "User-Agent": "snyk-scm-contributors-count-py"})
        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    body = json.loads(resp.read().decode() or "{}")
                break
            except urllib.error.HTTPError as e:
                msg = e.read().decode(errors="ignore")[:300]
                if e.code == 429 and attempt < 4:
                    wait = int(e.headers.get("Retry-After") or 30)
                    debug(f"Snyk 429, waiting {wait}s")
                    time.sleep(wait)
                    continue
                if e.code in (401, 403):
                    raise SystemExit(f"Snyk API {e.code} for {url}\n{msg}\n"
                                     "Check SNYK_TOKEN (Account settings > Auth Token / service account) "
                                     "and --snykApiUrl for your region.")
                raise RuntimeError(f"Snyk API {e.code} for {url}: {msg}")
        items.extend(body.get("data") or [])
        nxt = (body.get("links") or {}).get("next")
        if nxt:
            if nxt.startswith("http"):
                url = nxt
            else:
                nxt = nxt if nxt.startswith("/rest") else "/rest" + nxt
                url = f"{base}{nxt}"
        else:
            url = None
    return items


def snyk_orgs(base, token, group_id=None, org_ids=None):
    if org_ids:
        return [{"id": o, "name": o} for o in org_ids]
    path = (f"/groups/{group_id}/orgs?version={SNYK_API_VERSION}&limit=100" if group_id
            else f"/orgs?version={SNYK_API_VERSION}&limit=100")
    return [{"id": o["id"], "name": (o.get("attributes") or {}).get("name") or o["id"]}
            for o in snyk_get_all(base, token, path)]


def _repo_from_url(url):
    """https://github.com/Org/Repo(.git) or git@github.com:Org/Repo.git -> ('github.com', 'org/repo')"""
    if not url:
        return None, None
    u = url.strip()
    if u.startswith("git@"):
        host, _, path = u[4:].partition(":")
    else:
        u = u.split("://", 1)[-1]
        u = u.split("@", 1)[-1]                          # drop credentials
        host, _, path = u.partition("/")
    host = host.split(":")[0].lower()
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return host, None
    name = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    return host, f"{parts[0]}/{name}".lower()


def snyk_monitored_repos(base, token, scm_host, in_scope_keys, group_id=None, org_ids=None, quiet=False):
    """Returns {repo_key: set(snyk org names)} for in-scope GitHub repos that have a Snyk target."""
    matches = {}
    orgs = snyk_orgs(base, token, group_id, org_ids)
    if not quiet:
        print(f"Found {len(orgs)} Snyk org(s) visible to SNYK_TOKEN", file=sys.stderr)
    for i, org in enumerate(orgs, 1):
        debug(f"[{i}/{len(orgs)}] Snyk org {org['name']} ({org['id']})")
        try:
            targets = snyk_get_all(base, token, f"/orgs/{org['id']}/targets?version={SNYK_API_VERSION}&limit=100")
        except RuntimeError as err:
            debug(str(err))
            print(f"Failed retrieving Snyk targets for org {org['name']}", file=sys.stderr)
            continue
        for t in targets:
            a = t.get("attributes") or {}
            display = (a.get("display_name") or a.get("displayName") or "").strip().lower()
            url = a.get("url") or a.get("remoteUrl") or a.get("remote_url")
            host, from_url = _repo_from_url(url)
            key = None
            if from_url and host == scm_host and from_url in in_scope_keys:
                key = from_url                      # URL on the same SCM host (SCM or CLI/CI targets)
            elif display in in_scope_keys and (not host or host == scm_host):
                key = display                       # SCM integration target "owner/repo"
            if key:
                matches.setdefault(key, set()).add(org["name"])
    return matches


def per_repo_contributors(commits):
    emails = {_norm(c["commit"]["author"].get("email") or "") for c in commits}
    return {e for e in emails if e and not is_skipped_email(e)}


def finalize(cmap, exclusion_path):
    cmap = dedup_contributors_by_email(cmap)
    before = len(cmap)
    cmap = exclude_from_list_by_email(cmap, exclusion_path) if exclusion_path else cmap
    return cmap, before - len(cmap)


def emails_of(cmap):
    return {_norm(c["email"]) for c in cmap.values()}


def private_emails(cmap):
    return {_norm(c["email"]) for c in cmap.values()
            if any(r.lower().endswith("(private)") for r in c["reposContributedTo"])}


def snyk_coverage_report(repo_list, commits_cache, monitored, exclusion_path, as_json, out_dir=None):
    scanned = [r for r in repo_list if repo_key(r) in monitored]
    unscanned = [r for r in repo_list if repo_key(r) not in monitored]

    all_map, _ = finalize(build_contributor_map(repo_list, commits_cache), exclusion_path)
    scan_map, _ = finalize(build_contributor_map(scanned, commits_cache), exclusion_path)
    unscan_map, _ = finalize(build_contributor_map(unscanned, commits_cache), exclusion_path)

    all_e, scan_e, unscan_e = emails_of(all_map), emails_of(scan_map), emails_of(unscan_map)
    new_devs = sorted(unscan_e - scan_e)

    rows = []
    for r in repo_list:
        commits = commits_cache.get(repo_key(r), [])
        devs = per_repo_contributors(commits)
        rows.append({
            "repo": f"{r['owner']}/{r['name']}",
            "visibility": "Private" if r.get("private") else "Public",
            "archived": bool(r.get("archived")),
            "branch_scanned": r.get("scanned_branch") or r.get("default_branch") or "",
            "default_branch": r.get("default_branch") or "",
            "snyk_scanned": repo_key(r) in monitored,
            "snyk_orgs": ";".join(sorted(monitored.get(repo_key(r), []))),
            "contributors_90d": len(devs),
            "commits_90d": len(commits),
        })

    def cnt(lst, pred):
        return sum(1 for r in lst if pred(r))

    report = {
        "githubScope": {
            "totalRepos": len(repo_list),
            "privateRepos": cnt(repo_list, lambda r: r.get("private")),
            "publicRepos": cnt(repo_list, lambda r: not r.get("private")),
            "archivedRepos": cnt(repo_list, lambda r: r.get("archived")),
            "reposWithCommitsLast90d": cnt(repo_list, lambda r: commits_cache.get(repo_key(r))),
            "contributingDevelopers90d": len(all_e),
            "contributingDevelopers90dPrivateRepos": len(private_emails(all_map)),
        },
        "snykScanned": {
            "repos": len(scanned),
            "privateRepos": cnt(scanned, lambda r: r.get("private")),
            "reposWithCommitsLast90d": cnt(scanned, lambda r: commits_cache.get(repo_key(r))),
            "contributingDevelopers90d": len(scan_e),
            "contributingDevelopers90dPrivateRepos": len(private_emails(scan_map)),
        },
        "notScanned": {
            "repos": len(unscanned),
            "privateRepos": cnt(unscanned, lambda r: r.get("private")),
            "activeReposWithCommitsLast90d": cnt(unscanned, lambda r: commits_cache.get(repo_key(r))),
            "contributingDevelopers90d": len(unscan_e),
            "additionalDevelopersIfOnboarded": len(new_devs),
        },
        "repoCoveragePercent": round(100.0 * len(scanned) / len(repo_list), 2) if repo_list else 0.0,
        "repos": rows,
        "additionalDevelopersIfOnboarded": new_devs,
    }

    if out_dir:
        import csv
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "snyk-coverage-repos.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["repo"])
            w.writeheader()
            w.writerows(sorted(rows, key=lambda x: (x["snyk_scanned"], -x["contributors_90d"])))
        for fname, cmap in (("contributors-all.csv", all_map), ("contributors-snyk-scanned.csv", scan_map),
                            ("contributors-not-scanned.csv", unscan_map)):
            with open(os.path.join(out_dir, fname), "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["name", "email", "commits_90d", "repos"])
                for name, c in cmap.items():
                    w.writerow([name, c["email"], c["contributionsCount"], ";".join(c["reposContributedTo"])])

    if as_json:
        return report

    g, s, n = report["githubScope"], report["snykScanned"], report["notScanned"]
    print(f"\n{yellow('#### Snyk Coverage Report')}")
    print(blue("** GitHub scope vs repos monitored in Snyk. Contributors = unique authors with at least "
               "one commit on the default branch in the last 90 days **\n"))
    print(f"GitHub repos in scope                         : {g['totalRepos']}  "
          f"(private {g['privateRepos']}, public {g['publicRepos']}, archived {g['archivedRepos']})")
    print(f"GitHub repos with commits in last 90 days      : {g['reposWithCommitsLast90d']}")
    print(f"GitHub contributing developers (all repos)     : {g['contributingDevelopers90d']}  "
          f"(private repos: {g['contributingDevelopers90dPrivateRepos']})")
    print("")
    print(f"Repos scanned by Snyk                          : {s['repos']}  "
          f"({report['repoCoveragePercent']}% of repos, private {s['privateRepos']})")
    print(f"Contributing developers on Snyk-scanned repos  : {s['contributingDevelopers90d']}  "
          f"(private repos: {s['contributingDevelopers90dPrivateRepos']})")
    print("")
    print(f"Repos NOT scanned / not tested by Snyk         : {n['repos']}  "
          f"(private {n['privateRepos']}, active in last 90 days {n['activeReposWithCommitsLast90d']})")
    print(f"Contributing developers on NOT-scanned repos   : {n['contributingDevelopers90d']}")
    print(f"Additional developers if all repos onboarded   : {n['additionalDevelopersIfOnboarded']}")

    print(f"\n{yellow('## Not scanned by Snyk (sorted by contributors, 90d)')}")
    for r in sorted((x for x in rows if not x["snyk_scanned"]), key=lambda x: -x["contributors_90d"]):
        flags = ", archived" if r["archived"] else ""
        print(f"{r['repo']}({r['visibility']}{flags}) - Contributors: {r['contributors_90d']}, "
              f"Commits: {r['commits_90d']}")
    print(f"\n{yellow('## Scanned by Snyk')}")
    for r in sorted((x for x in rows if x["snyk_scanned"]), key=lambda x: -x["contributors_90d"]):
        print(f"{r['repo']}({r['visibility']}) - Contributors: {r['contributors_90d']} - Snyk org(s): {r['snyk_orgs']}")
    if out_dir:
        print(f"\nCSV reports written to {os.path.abspath(out_dir)}")
    return report


# ----------------------------------------------------------------------------- common utils

def _norm(email):
    return email.replace(" ", "", 1)      # JS String.replace(' ', '') -> first occurrence only


def return_key_if_email_found(cmap, email):
    for key, value in cmap.items():
        if _norm(value["email"]) == _norm(email):
            return key
    return ""


def dedup_repos(lst):
    return list(dict.fromkeys(lst))


def dedup_contributors_by_email(cmap):
    result = {}
    for username in list(cmap.keys()):
        if username not in cmap:                  # deleted earlier during iteration
            continue
        contributor = cmap.pop(username)
        dup = return_key_if_email_found(cmap, contributor["email"])
        if dup:
            while dup:
                entry = cmap[dup]
                contributor["reposContributedTo"] = dedup_repos(
                    contributor["reposContributedTo"] + entry["reposContributedTo"])
                contributor["contributionsCount"] += entry["contributionsCount"]
                del cmap[dup]
                result[username] = contributor
                dup = return_key_if_email_found(cmap, contributor["email"])
        else:
            result[username] = contributor
    return result


def exclude_from_list_by_email(cmap, path):
    if not path:
        return cmap
    try:
        with open(os.path.normpath(path)) as f:
            emails = [x for x in f.read().split("\n") if x]
    except OSError as err:
        debug(f"Issue loading exclusion list\n{err}")
        print("Issue loading exclusion list")
        emails = []
    for email in emails:
        key = return_key_if_email_found(cmap, email)
        if key:
            debug(f"Excluding {email} from map using key {key}")
            del cmap[key]
    return cmap


def calculate_summary_stats(cmap, exclusion_count):
    repo_list = []
    for c in cmap.values():
        repo_list += c["reposContributedTo"]
    repo_list = dedup_repos(repo_list)
    return {"contributorsCount": len(cmap), "repoCount": len(repo_list), "repoList": repo_list,
            "exclusionCount": exclusion_count, "contributorsDetails": cmap}


# ----------------------------------------------------------------------------- output

def printout_results(res, as_json=False):
    buckets = {"(private)": [], "(public)": [], "(undefined)": []}

    def contributor_count_for_repo(repo_name):
        lst = []
        for c in res["contributorsDetails"].values():
            for r in c["reposContributedTo"]:
                if repo_name.lower() in r.lower():
                    lst.append(c["email"])
        return lst

    def filtered_repo_list(ftype):
        out = []
        for repo in res["repoList"]:
            if repo.lower().endswith(ftype.lower()):
                details = contributor_count_for_repo(repo.lower())
                out.append(f"{repo} - Contributors count: {len(details)}")
                for e in details:
                    if e not in buckets[ftype]:
                        buckets[ftype].append(e)
        return out

    output = {
        "privateRepoList": filtered_repo_list("(private)"),
        "publicRepoList": filtered_repo_list("(public)"),
        "contributorsCount": res["contributorsCount"],
        "repoCount": res["repoCount"],
        "undefinedRepoList": filtered_repo_list("(undefined)"),
        "exclusionCount": res["exclusionCount"],
        "contributorsDetails": [[k, v] for k, v in res["contributorsDetails"].items()],
    }
    if as_json:
        print(json.dumps(output, indent=4))
        return

    def summary():
        print(f"\n{yellow('#### Summary')}")
        print(blue("** This summary indicates the number of contributors who have made at least one "
                   "commit in the last 90 days to repositories **\n"))
        print(f"Private Repos Contributors Count: {len(buckets['(private)'])}")
        print(f"Public Repos Contributors Count: {len(buckets['(public)'])}")
        if output["undefinedRepoList"]:
            print(f"Undefined Repos Contributors Count: {len(buckets['(undefined)'])}")
        print(f"Total Unique Contributors Count for Private and Public repositories: {output['contributorsCount']}")
        print(f"Private Repository Count: {len(output['privateRepoList'])}")
        print(f"Public Repository Count: {len(output['publicRepoList'])}")
        if output["undefinedRepoList"]:
            print(f"Undefined Repository Count: {len(output['undefinedRepoList'])}")
        print(f"Total Repository Count: {output['repoCount']}")
        print(f"Exclusion Count: {output['exclusionCount']}")

    summary()
    if output["contributorsCount"] > 0:
        print(f"\n\n{yellow('### Details:')}")
        print("## Repository List\n")
        print("# Private Repositories:")
        print("\n".join(output["privateRepoList"]) + "\n")
        print("# Public Repositories:")
        print("\n".join(output["publicRepoList"]) + "\n")
        if output["undefinedRepoList"]:
            print("# Undefined Repositories:")
            print("\n".join(output["undefinedRepoList"]) + "\n")
        print("\n## Contributors details")
        print(json.dumps(output["contributorsDetails"], indent=4))
    if output["repoCount"] > 0:
        summary()


# ----------------------------------------------------------------------------- main (SCMHandler.scmContributorCount)

def quiet_mode(args):
    return DEBUG or args.json


def print_branch_summary(repo_list):
    print(f"\n{yellow('#### Branch used per repository')}")
    for r in repo_list:
        default = r.get("default_branch") or "?"
        used = r.get("scanned_branch") or default
        tag = "" if used == default else f"  (default: {default})"
        print(f"{r['owner']}/{r['name']}: {used}{tag}")


def three_months_date():
    return (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    p = argparse.ArgumentParser(description="Count contributors (Python port of snyk-scm-contributors-count).")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--token", default=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"),
                        help="Github token (or export GH_TOKEN)")
        sp.add_argument("--orgs", help="Comma-separated list of organizations to count contributors for")
        sp.add_argument("--repo", help="[Optional] A single repo to count contributors for (needs one --orgs)")
        sp.add_argument("--exclusionFilePath", help="[Optional] Exclusion list filepath (one email per line)")
        sp.add_argument("--json", action="store_true", help="[Optional] JSON output")
        sp.add_argument("--branch", default="default",
                        help="[Optional] 'default' (repo default branch, same as Snyk - DEFAULT), "
                             "'latest' (branch with the most recent commit), or a branch name")

    gh = sub.add_parser("github", help="Count contributors for Github")
    common(gh)
    ghe = sub.add_parser("github-enterprise", help="Count contributors for Github Enterprise Server")
    common(ghe)
    ghe.add_argument("--url", required=True, help="Github Enterprise base URL, e.g. https://ghe.company.com")
    ghe.add_argument("--fetchAllOrgs", action="store_true",
                     help="[Optional] Count across ALL orgs on the server (/organizations; admin token)")
    for sp in (gh, ghe):
        g = sp.add_argument_group("Snyk coverage (optional, needs SNYK_TOKEN env var)")
        g.add_argument("--snyk", action="store_true",
                       help="Compare the GitHub scope with repos monitored in Snyk")
        g.add_argument("--snykGroupId", help="Only use Snyk orgs in this group")
        g.add_argument("--snykOrgIds", help="Only use these Snyk org IDs (comma-separated)")
        g.add_argument("--snykApiUrl", default=os.environ.get("SNYK_API_URL", "https://api.snyk.io"),
                       help="Snyk API base (EU: https://api.eu.snyk.io, AU: https://api.au.snyk.io)")
        g.add_argument("--outputDir", help="Write CSV reports (coverage per repo, contributor lists) here")
    args = p.parse_args()

    if not args.token:
        p.error("--token is required (or export GH_TOKEN)")

    if args.cmd == "github":
        api = "https://api.github.com/"
        scm_host = "github.com"
        fetch_all = False
    else:
        global SCM
        SCM = "Github Enterprise"
        api = args.url.rstrip("/") + "/api/v3/"
        scm_host = args.url.split("://", 1)[-1].split("/")[0].split(":")[0].lower()
        fetch_all = args.fetchAllOrgs

    global BRANCH_MODE
    BRANCH_MODE = args.branch
    if BRANCH_MODE != "default" and not quiet_mode(args):
        print(f"Branch mode: {BRANCH_MODE} (note: Snyk licensing counts the DEFAULT branch only)", file=sys.stderr)

    snyk_token = os.environ.get("SNYK_TOKEN")
    if args.snyk and args.json:
        global ERR_OUT
        ERR_OUT = sys.stderr
    if args.snyk and not snyk_token:
        p.error("--snyk needs SNYK_TOKEN exported:  export SNYK_TOKEN=<snyk api token>")

    orgs = args.orgs.split(",") if args.orgs else None
    quiet = DEBUG or args.json
    spinner = Spinner(quiet)
    debug(f"Options: Orgs: {orgs}, Repo: {args.repo}, Exclusion File: {args.exclusionFilePath}")

    repo_list, commits_cache = fetch_github_repos_and_commits(
        api, args.token, orgs, args.repo, three_months_date(), fetch_all)
    contributors = build_contributor_map(repo_list, commits_cache)
    spinner.succeed("Retrieving projects/orgs from the SCM with commits in last 90 days")

    if args.snyk:
        monitored = snyk_monitored_repos(
            args.snykApiUrl.rstrip("/"), snyk_token, scm_host, {repo_key(r) for r in repo_list},
            args.snykGroupId, args.snykOrgIds.split(",") if args.snykOrgIds else None, quiet)
        spinner.succeed("Loading snyk monitored repos list")
        report = snyk_coverage_report(repo_list, commits_cache, monitored, args.exclusionFilePath,
                                      args.json, args.outputDir)
        if args.json:
            print(json.dumps({"snykCoverage": report}, indent=4))
            return
        print(f"\n{yellow('#### GitHub contributors (upstream snyk-scm-contributors-count output)')}")

    contributors = dedup_contributors_by_email(contributors)
    before = len(contributors)
    spinner.succeed("Removing duplicate contributors")

    if args.exclusionFilePath:
        contributors = exclude_from_list_by_email(contributors, args.exclusionFilePath)
        spinner.succeed("Applying exclusion list ")

    printout_results(calculate_summary_stats(contributors, before - len(contributors)), args.json)
    if BRANCH_MODE != "default" and not args.json:
        print_branch_summary(repo_list)


if __name__ == "__main__":
    main()
