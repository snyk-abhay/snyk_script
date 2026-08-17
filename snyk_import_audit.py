#!/usr/bin/env python3
"""
Snyk Import Audit

Reconciles what exists in GitHub against what exists in Snyk, and classifies
every repo into one coverage bucket.

WHAT IT ANSWERS
---------------
  Source          Meaning                        Comes from
  --------------  -----------------------------  --------------------------
  GitHub + Snyk   Tested                         repo in both systems
  GitHub only     Not tested (never imported)    repo absent from Snyk
  Snyk only       Edge case (no GitHub link)     Snyk target with no repo

and within the repos Snyk knows about:

  OK (SCA + SAST)         both an Open Source and a Snyk Code project exist
  MISSING CODE ANALYSIS   Open Source only -- the mandatory PR check for
                          Snyk Code can never fire for these
  SAST ONLY               Snyk Code only (fine if the plan excludes Open Source)
  EMPTY TARGET            target exists but has zero projects (failed import)
  NOT IMPORTED            in GitHub, absent from Snyk entirely

The two axes are kept independent: `status` is the coverage verdict and
`source` says which systems know the repo. A Snyk target with no GitHub repo
is `source == "Snyk only"`, whatever its coverage.

plus, optionally, whether each repo still has a working Snyk webhook. A repo
with no webhook is silently stale: Snyk keeps reporting the last scan and
never picks up new commits.

SETUP
-----
1. Generate a Snyk API token with access to the whole Group (a Group service
   account is cleanest: Group Settings > Service Accounts).
2. Confirm your API host. If your app URL is app.us.snyk.io the API host is
   api.us.snyk.io; likewise api.eu.snyk.io / api.au.snyk.io. A token used
   against the wrong region returns 401.
3. pip install requests
4. export SNYK_TOKEN=xxxxxxxx
   export SNYK_GROUP_ID=xxxxxxxx
   export SNYK_API_BASE=https://api.us.snyk.io   # default: https://api.snyk.io

   # Optional -- without these the GitHub-side buckets are skipped and every
   # repo is reported from Snyk's point of view only.
   export GITHUB_TOKEN=ghp_xxxx
   export GITHUB_ORG=my-org,my-other-org         # comma-separated
   export GITHUB_API=https://api.github.com # for GHE

   # Optional -- one extra GitHub call per repo, so it is off by default.
   # Needs admin rights on the repo; without them the result is "unknown",
   # never "missing", so a permissions gap cannot masquerade as a finding.
   export CHECK_WEBHOOKS=1

5. python3 audit/snyk_import_audit.py > audit_report.csv
   (progress and the summary table go to the terminal; only CSV rows to the file)
"""

import csv
import os
import sys
import time

import requests

API_BASE = os.environ.get("SNYK_API_BASE", "https://api.snyk.io").rstrip("/")
API_VERSION = "2024-10-15"
SAST_TYPE = "sast"  # the only value meaning "Snyk Code project"; every other type (maven, npm, gradle, pip, yarn, nuget, dockerfile, ...) is Open Source / container / IaC

GITHUB_API = os.environ.get("GITHUB_API", "https://api.github.com").rstrip("/")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_ORGS = [o.strip() for o in os.environ.get("GITHUB_ORG", "").split(",") if o.strip()]
CHECK_WEBHOOKS = os.environ.get("CHECK_WEBHOOKS", "").lower() in ("1", "true", "yes")

try:
    TOKEN = os.environ["SNYK_TOKEN"]
    GROUP_ID = os.environ["SNYK_GROUP_ID"]
except KeyError as e:
    sys.exit(f"Missing required environment variable: {e}. See the setup notes at the top of this file.")

HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Content-Type": "application/vnd.api+json",
}

GH_HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def attr(d, *keys, default=""):
    """Try several possible attribute key spellings, return the first hit."""
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _resolve_next(next_link):
    if next_link.startswith("http"):
        return next_link
    if next_link.startswith("/rest/"):
        return API_BASE + next_link
    return API_BASE + "/rest" + next_link  # docs show relative links without the /rest prefix


def get(url, params=None):
    for _ in range(5):
        resp = requests.get(url, headers=HEADERS, params=params, timeout=30)
        if resp.status_code == 429:
            time.sleep(int(resp.headers.get("Retry-After", 5)))
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError(f"Repeated 429 (rate limited) calling {url}")


def paginate(path, params):
    url = f"{API_BASE}{path}"
    while url:
        body = get(url, params=params)
        for item in body.get("data", []):
            yield item
        next_link = (body.get("links") or {}).get("next")
        if not next_link:
            break
        url = _resolve_next(next_link)
        params = None  # next link already carries the query string


def list_orgs_in_group(group_id):
    return list(paginate(f"/rest/groups/{group_id}/orgs", {"version": API_VERSION, "limit": 100}))


def list_targets(org_id):
    return list(paginate(f"/rest/orgs/{org_id}/targets", {"version": API_VERSION, "limit": 100}))


def list_projects(org_id):
    return list(paginate(f"/rest/orgs/{org_id}/projects", {"version": API_VERSION, "limit": 100}))


# ---------------------------------------------------------------------------
# GitHub side
# ---------------------------------------------------------------------------

def gh_get(url, params=None):
    """GET with retry on secondary rate limits. Returns (json, response)."""
    for _ in range(5):
        resp = requests.get(url, headers=GH_HEADERS, params=params, timeout=30)
        # Primary rate limit: remaining hits zero and the reset time is in a header.
        if resp.status_code in (403, 429) and resp.headers.get("X-RateLimit-Remaining") == "0":
            reset = int(resp.headers.get("X-RateLimit-Reset", 0))
            wait = max(reset - int(time.time()), 1)
            print(f"    GitHub rate limited, sleeping {wait}s", file=sys.stderr)
            time.sleep(min(wait, 300))
            continue
        return resp
    raise RuntimeError(f"Repeated rate limiting calling {url}")


def gh_paginate(url, params=None):
    while url:
        resp = gh_get(url, params=params)
        resp.raise_for_status()
        for item in resp.json():
            yield item
        # GitHub paginates via the Link header, not a body field.
        url = resp.links.get("next", {}).get("url")
        params = None


class GitHubOwnerError(Exception):
    """A GitHub owner could not be listed, with an actionable reason."""


def resolve_owner_repos_url(owner):
    """Return the correct repos URL for `owner`, org or user.

    GitHub 404s /orgs/{name} for three different reasons -- wrong name, it is
    a user account rather than an org, and 'your token cannot see it' -- so
    probe to tell them apart instead of surfacing a bare 404.
    """
    if gh_get(f"{GITHUB_API}/orgs/{owner}").status_code != 404:
        return f"{GITHUB_API}/orgs/{owner}/repos"

    user = gh_get(f"{GITHUB_API}/users/{owner}")
    if user.ok and user.json().get("type") == "User":
        return f"{GITHUB_API}/users/{owner}/repos"
    if user.status_code == 404:
        raise GitHubOwnerError(
            f"'{owner}' does not exist on GitHub, or your token cannot see it. "
            "Check for a typo; if it is a private org, confirm the token is "
            "SSO-authorized for it.")
    raise GitHubOwnerError(f"'{owner}' lookup failed: HTTP {user.status_code}")


def list_github_repos(org):
    return list(gh_paginate(resolve_owner_repos_url(org),
                            {"per_page": 100, "type": "all"}))


def has_snyk_webhook(full_name):
    """'yes' / 'no' / 'unknown'.

    Returns 'unknown' rather than 'no' when we lack admin rights, so a
    permissions gap is never reported as a missing webhook.
    """
    resp = gh_get(f"{GITHUB_API}/repos/{full_name}/hooks", {"per_page": 100})
    if resp.status_code in (403, 404):
        return "unknown"
    if not resp.ok:
        return "unknown"
    for hook in resp.json():
        url = (hook.get("config") or {}).get("url", "")
        if "snyk.io" in url:
            return "yes" if hook.get("active") else "no"
    return "no"


def norm(name):
    """Normalise a repo identifier for matching across the two systems."""
    return (name or "").strip().lower()


# ---------------------------------------------------------------------------

def main():
    if GITHUB_ORGS and not GITHUB_TOKEN:
        print("GITHUB_ORG is set but GITHUB_TOKEN is not -- skipping the GitHub side.",
              file=sys.stderr)

    use_github = bool(GITHUB_TOKEN and GITHUB_ORGS)

    # --- collect GitHub repos -------------------------------------------------
    gh_repos = {}  # normalised full_name -> repo object
    if use_github:
        failed_orgs = []
        for org in GITHUB_ORGS:
            # One unreachable owner must not discard the repos already
            # collected from the others -- report it and carry on.
            try:
                repos = list_github_repos(org)
            except (GitHubOwnerError, requests.HTTPError) as e:
                print(f"GitHub {org}: SKIPPED -- {e}", file=sys.stderr)
                failed_orgs.append(org)
                continue
            print(f"GitHub {org}: {len(repos)} repos", file=sys.stderr)
            for r in repos:
                gh_repos[norm(r.get("full_name"))] = r

        if failed_orgs:
            print(f"WARNING: {len(failed_orgs)} owner(s) could not be listed "
                  f"({', '.join(failed_orgs)}). Repos under them are missing from "
                  "this report, so 'Snyk only' will be overstated.", file=sys.stderr)
        if not gh_repos:
            print("No GitHub repos retrieved -- disabling the GitHub side.", file=sys.stderr)
            use_github = False
    else:
        print("GitHub side disabled (set GITHUB_TOKEN and GITHUB_ORG to enable). "
              "'Not imported' and webhook columns will be blank.", file=sys.stderr)

    # Bare repo name -> full name, so Snyk targets recorded without an owner
    # prefix still match. Ambiguous bare names are dropped rather than guessed.
    bare_index = {}
    for full in gh_repos:
        bare = full.split("/")[-1]
        bare_index[bare] = None if bare in bare_index else full

    writer = csv.writer(sys.stdout)
    writer.writerow([
        "org_name", "org_id", "repo_name", "target_id", "origin",
        "project_count", "has_open_source", "has_snyk_code",
        "source", "webhook", "archived", "status",
    ])

    orgs = list_orgs_in_group(GROUP_ID)
    print(f"Found {len(orgs)} org(s) in group {GROUP_ID}", file=sys.stderr)

    total_targets = 0
    flag_counts = {}
    source_counts = {"GitHub + Snyk": 0, "GitHub only": 0, "Snyk only": 0}
    matched_gh = set()
    webhook_counts = {}

    for org in orgs:
        org_id = org["id"]
        org_name = attr(org.get("attributes", {}), "name", "slug", default=org_id)

        targets = {t["id"]: t for t in list_targets(org_id)}
        projects = list_projects(org_id)
        print(f"  {org_name}: {len(targets)} targets, {len(projects)} projects", file=sys.stderr)

        by_target = {}
        for p in projects:
            tid = p.get("relationships", {}).get("target", {}).get("data", {}).get("id")
            ptype = p.get("attributes", {}).get("type", "")
            if tid:
                by_target.setdefault(tid, []).append(ptype)

        for target_id, target in targets.items():
            total_targets += 1
            t_attrs = target.get("attributes", {})
            types = by_target.get(target_id, [])
            has_sast = SAST_TYPE in types
            has_open_source = any(t and t != SAST_TYPE for t in types)
            repo_name = attr(t_attrs, "displayName", "display_name", "name", default=target_id)
            origin = attr(t_attrs, "origin")

            # --- match this Snyk target back to a GitHub repo ---
            key = norm(repo_name)
            gh = gh_repos.get(key)
            if gh is None and "/" not in key:
                full = bare_index.get(key)
                gh = gh_repos.get(full) if full else None
            if gh is not None:
                matched_gh.add(norm(gh.get("full_name")))

            if not use_github:
                source = ""
            elif gh is not None:
                source = "GitHub + Snyk"
            else:
                source = "Snyk only"
            if source:
                source_counts[source] = source_counts.get(source, 0) + 1

            # --- classify coverage ---
            if not types:
                status = "EMPTY TARGET (0 projects)"
            elif has_open_source and has_sast:
                status = "OK (SCA + SAST)"
            elif has_open_source:
                status = "MISSING CODE ANALYSIS (SCA only)"
            elif has_sast:
                status = "SAST ONLY (fine if plan excludes Open Source)"
            else:
                status = "EMPTY TARGET (0 projects)"

            # Deliberately NOT folded into `status`: whether GitHub knows this
            # repo is already carried by the `source` column, and encoding it
            # twice would split each coverage count across two labels.

            webhook = ""
            if CHECK_WEBHOOKS and gh is not None:
                webhook = has_snyk_webhook(gh["full_name"])
                webhook_counts[webhook] = webhook_counts.get(webhook, 0) + 1

            flag_counts[status] = flag_counts.get(status, 0) + 1

            writer.writerow([
                org_name, org_id, repo_name, target_id, origin,
                len(types), has_open_source, has_sast,
                source, webhook, gh.get("archived", "") if gh else "", status,
            ])

    # --- GitHub repos that Snyk has never seen --------------------------------
    archived_not_imported = 0
    if use_github:
        for key, gh in sorted(gh_repos.items()):
            if key in matched_gh:
                continue
            source_counts["GitHub only"] += 1
            status = "NOT IMPORTED (in GitHub, absent from Snyk)"
            flag_counts[status] = flag_counts.get(status, 0) + 1
            if gh.get("archived"):
                archived_not_imported += 1

            webhook = ""
            if CHECK_WEBHOOKS:
                webhook = has_snyk_webhook(gh["full_name"])
                webhook_counts[webhook] = webhook_counts.get(webhook, 0) + 1

            writer.writerow([
                "", "", gh.get("full_name", key), "", "github",
                0, False, False,
                "GitHub only", webhook, gh.get("archived", ""), status,
            ])

    # --- summary --------------------------------------------------------------
    out = sys.stderr
    print(f"\nDone. {total_targets} Snyk target(s) scanned.", file=out)

    if use_github:
        print("\n  Source          Meaning                        Repo count", file=out)
        print("  --------------  -----------------------------  ----------", file=out)
        for src, meaning in (
            ("GitHub + Snyk", "Tested"),
            ("GitHub only", "Not tested"),
            ("Snyk only", "Edge case (no GitHub link)"),
        ):
            print(f"  {src:<14}  {meaning:<29}  {source_counts.get(src, 0):>10,}", file=out)
        if archived_not_imported:
            print(f"\n  Note: {archived_not_imported:,} of the 'GitHub only' repos are archived "
                  "and may not need importing.", file=out)

    print("\n  Coverage breakdown", file=out)
    print("  ------------------", file=out)
    for status, count in sorted(flag_counts.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>10,}  {status}", file=out)

    if CHECK_WEBHOOKS:
        print("\n  Snyk webhook present", file=out)
        print("  --------------------", file=out)
        for label, count in sorted(webhook_counts.items(), key=lambda kv: -kv[1]):
            note = "  (no admin rights on the repo)" if label == "unknown" else ""
            print(f"  {count:>10,}  {label}{note}", file=out)
    elif use_github:
        print("\n  Webhook check skipped. Set CHECK_WEBHOOKS=1 to enable "
              "(one extra GitHub call per repo).", file=out)


if __name__ == "__main__":
    main()
