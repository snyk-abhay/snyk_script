"""
Snyk Auto-Onboarding / Repair Loop

Runs unattended (every 6 hours by default). Finds repos Snyk has discovered but
never imported, plus imported repos that scanned nothing or lost their webhook,
and repairs them.

FLOW
----
1. Authenticate to Snyk at GROUP level, and to GitHub.

2. Build the in-scope inventory from Snyk's DISCOVERED repository assets across
   the group, merged with the target/project state of what has been imported.

   Snyk's model is target -> projects: a target is one repo, each project is
   one scan of one surface inside it (npm, maven, sast, dockerfile, ...). But a
   target only exists once a repo is imported, so scoping on targets alone
   hides every repo that still needs onboarding. Asset discovery closes that
   gap; if it is unavailable the run falls back to targets only.

   Note: the targets endpoint defaults to exclude_empty=true, which hides the
   zero-project targets this tool exists to find. list_targets() overrides it.

3. Import pass. A discovered repo with no target has never been onboarded.

4. Coverage pass. A target with zero projects was imported but scanned nothing
   -- the import failed midway, or there is nothing scannable.

5. Webhook pass. For each already-imported repo, check whether a Snyk webhook
   exists on GitHub. A missing webhook means the repo is silently stale: Snyk
   keeps showing the last scan and never sees new commits. Skipped for
   never-imported repos, whose import creates the hook anyway.

6. Report the buckets, act on the chosen ones, follow each import job to
   completion, re-check, then write the CSV last so it reflects reality.

PARAMETERS
----------
Required environment:

  SNYK_TOKEN            Snyk API token. MUST be the classic 36-character UUID
                        from Account Settings > General > Auth Token. The newer
                        snyk_uat.* / snyk_sat.* tokens authenticate for reads
                        but the v1 import endpoint rejects them with a
                        misleading 401 "Invalid credentials".
  SNYK_GROUP_ID         Group whose orgs define the scope.
  GITHUB_TOKEN          Classic PAT with `repo` + `admin:repo_hook`, issued by
                        an account that ADMINS the repos -- scopes alone do not
                        grant access. Without admin rights every webhook reads
                        back as "unknown". Required unless CHECK_WEBHOOKS=0.

Optional environment:

  SNYK_API_BASE         https://api.snyk.io (default) | api.eu | api.au |
                        api.us. Tokens are region-scoped; the wrong host 401s.
                        No /v1 suffix.
  SNYK_IMPORT_ORG_ID    Org for newly discovered repos when the group has more
                        than one org and the owner cannot be matched to an
                        existing org. Unnecessary for single-org groups.
  GITHUB_API_BASE       https://api.github.com (default). Set for GitHub
                        Enterprise.
  CHECK_WEBHOOKS        1 (default) | 0 to skip the webhook pass entirely.
  MAX_ACTIONS_PER_RUN   50 (default). Cap on imports per run; the remainder is
                        picked up next run. Stops a misconfiguration from
                        mass-importing.
  IMPORT_DELAY          2 (default). Seconds between imports, to pace limits.
  IMPORT_JOB_TIMEOUT    180 (default). Seconds to follow an import job before
                        giving up on in-run verification. A job still running
                        is reported as "timeout", not failed, and re-verified
                        next run.
  IMPORT_POLL_INTERVAL  5 (default). Seconds between job status polls.
  EXCLUDE_REPOS         Comma-separated globs, e.g. my-org/sandbox-*,my-org/tmp-*
  INCLUDE_ARCHIVED      1 to also act on archived repos (skipped by default).
  LIST_LIMIT            25 (default). Repo names printed per bucket before
                        truncating with "... and N more".
  ONBOARD_CSV           onboard-report.csv (default). FILENAME only, not a path.
  ONBOARD_STATE_FILE    .onboard-state.json (default). FILENAME only. A
                        directory component is stripped: this runs unattended
                        from cron, so accepting a path from the environment
                        would be a traversal write primitive. Symlink the file
                        to relocate it.
  NO_COLOR              Set to disable colour. Colour is off automatically when
                        stderr is not a terminal, so cron logs stay clean.

Command line:

  --apply               Actually import. Without it the run is a DRY RUN.
  --scope {webhook,unscanned,both,none}
                        What to act on, without prompting:
                          webhook    imported repos whose webhook is missing
                          unscanned  no target, or a target with 0 projects
                          both       both of the above
                          none       report + CSV only, change nothing
                        Required for cron. Interactive runs prompt; other
                        non-interactive runs default to "both".
  --schedule INTERVAL   Loop in-process at this interval, e.g. 6h / 90m / 3600.
                        Prefer cron where available.

USAGE
-----
  pip install requests

  export SNYK_TOKEN=<36-char-uuid>
  export SNYK_GROUP_ID=<group uuid>
  export GITHUB_TOKEN=<classic PAT>

  python3 snyk_auto_onboard.py                        # dry run, prompts
  python3 snyk_auto_onboard.py --scope none           # report + CSV only
  python3 snyk_auto_onboard.py --apply --scope both   # repair everything
  python3 snyk_auto_onboard.py --apply --scope webhook  # webhooks only

SCHEDULING EVERY 6 HOURS
------------------------
Cron is preferred -- each run is independent and survives reboots. --scope is
required here, otherwise the run would wait on a prompt nobody answers:

  0 */6 * * * cd /path/to/auto-onboard && /usr/bin/env \\
    SNYK_TOKEN=... SNYK_GROUP_ID=... GITHUB_TOKEN=... \\
    python3 snyk_auto_onboard.py --apply --scope both \\
    >> /var/log/snyk-onboard.log 2>&1

Or in-process, for a container or systemd unit:

  python3 snyk_auto_onboard.py --apply --scope both --schedule 6h

ORG ROUTING
-----------
An imported repo is re-imported into the org its target already lives in. A
newly discovered repo goes to the org already holding repos from the same
GitHub owner, falling back to the group's only org, then SNYK_IMPORT_ORG_ID.

RETRY POLICY
------------
Repos are retried every run, indefinitely -- a repo with no manifest today may
gain one next month. Nothing is parked. Attempt counters reset once a repo
verifies clean, and repos still broken after 5 attempts are called out as
probably needing a human.

RESTORING A MISSING WEBHOOK
---------------------------
A plain re-import CANNOT restore a webhook removed on the GitHub side: Snyk
returns 409 (target already exists) and changes nothing. The only API route is
to delete the target and import it fresh, so choosing the "webhook" bucket
does exactly that.

Be aware this permanently loses issue history, first-seen dates, project-level
ignores and project IDs for those repos. The guards are that --apply is
required (runs are a dry run by default), you pick the bucket explicitly, and
every deletion is logged as it happens.
"""

import argparse
import csv
import fnmatch
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

API_BASE = os.environ.get("SNYK_API_BASE", "https://api.snyk.io").rstrip("/")
API_VERSION = "2024-10-15"

GITHUB_API_BASE = os.environ.get("GITHUB_API_BASE", "https://api.github.com").rstrip("/")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

MAX_ACTIONS_PER_RUN = int(os.environ.get("MAX_ACTIONS_PER_RUN", "50"))
IMPORT_DELAY = float(os.environ.get("IMPORT_DELAY", "2"))
CHECK_WEBHOOKS = os.environ.get("CHECK_WEBHOOKS", "1").lower() in ("1", "true", "yes")
INCLUDE_ARCHIVED = os.environ.get("INCLUDE_ARCHIVED", "").lower() in ("1", "true", "yes")
EXCLUDE_REPOS = [p.strip().lower() for p in os.environ.get("EXCLUDE_REPOS", "").split(",") if p.strip()]

# Repos that have failed this many times are still retried (policy: retry
# forever) but are called out in the summary as needing a human.
ATTENTION_THRESHOLD = 5

# How many repo names to print per bucket before truncating.
LIST_LIMIT = int(os.environ.get("LIST_LIMIT", "25"))

# Deleting targets is destructive, so its cap is deliberately much lower than
# MAX_ACTIONS_PER_RUN -- a misfire should cost a handful of repos, not fifty.

# How long to follow an import job before giving up on in-run verification.
IMPORT_JOB_TIMEOUT = int(os.environ.get("IMPORT_JOB_TIMEOUT", "180"))
IMPORT_POLL_INTERVAL = float(os.environ.get("IMPORT_POLL_INTERVAL", "5"))

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _resolve_state_file():
    """Build the state file path. Only a FILENAME is taken from the environment.

    This script writes to this path unattended, often from cron, so no
    directory component is accepted from the environment at all: os.path.basename
    strips any path away, and the result is joined to a fixed directory. That
    makes traversal structurally impossible rather than merely validated
    against -- there is no input through which a caller could escape SCRIPT_DIR.

    To keep state elsewhere (a writable volume, /var/lib/...), symlink
    .onboard-state.json in this directory to the real location.
    """
    raw = os.environ.get("ONBOARD_STATE_FILE", "").strip()
    if not raw:
        return os.path.join(SCRIPT_DIR, ".onboard-state.json")

    name = os.path.basename(raw)
    if not name.endswith(".json") or (name.startswith(".") and name != ".onboard-state.json"):
        sys.exit("ONBOARD_STATE_FILE must be a plain *.json filename, not a path. "
                 "See the note in _resolve_state_file().")
    return os.path.join(SCRIPT_DIR, name)


STATE_FILE = _resolve_state_file()


def _resolve_csv_file():
    """CSV report path. Filename only, same traversal reasoning as the state file."""
    raw = os.environ.get("ONBOARD_CSV", "").strip()
    name = os.path.basename(raw) if raw else "onboard-report.csv"
    if not name.endswith(".csv"):
        sys.exit("ONBOARD_CSV must be a plain *.csv filename, not a path.")
    return os.path.join(SCRIPT_DIR, name)


CSV_FILE = _resolve_csv_file()


# Colour only when attached to a terminal, and honour NO_COLOR. Cron logs stay
# free of escape codes.
_COLOR = sys.stderr.isatty() and not os.environ.get("NO_COLOR")


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def dim(t):    return _c("2", t)
def bold(t):   return _c("1", t)
def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def red(t):    return _c("31", t)
def cyan(t):   return _c("36", t)


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"{dim(ts)}  {msg}", file=sys.stderr, flush=True)


def head(title):
    """Section header, so a run reads as distinct stages rather than a wall."""
    print(f"\n{bold(cyan('▸ ' + title))}", file=sys.stderr, flush=True)


def item(label, value, style=None):
    styled = style(str(value)) if style else str(value)
    print(f"   {label:<16} {styled}", file=sys.stderr, flush=True)


def log_ok(msg):   log(f"{green('✓')} {msg}")
def log_warn(msg): log(f"{yellow('!')} {yellow(msg)}")
def log_fail(msg): log(f"{red('✗')} {msg}")


def norm(name):
    return (name or "").strip().lower()


def excluded(full_name):
    return any(fnmatch.fnmatch(norm(full_name), pat) for pat in EXCLUDE_REPOS)


# ---------------------------------------------------------------------------
# Snyk
# ---------------------------------------------------------------------------

# Resolved once by preflight() and reused for the rest of the run.
_AUTH_SCHEME = None


def snyk_auth_value(token, scheme=None):
    """Build the Authorization header value.

    Snyk accepts two schemes and which one a given token wants is not reliably
    predictable from its prefix, so preflight() probes both and pins the answer
    in _AUTH_SCHEME rather than guessing here.
    """
    token = (token or "").strip()
    scheme = scheme or _AUTH_SCHEME
    if scheme:
        return f"{scheme} {token}"
    # Pre-probe default: legacy scheme, which classic UUID keys require.
    return f"token {token}"


def detect_auth_scheme():
    """Probe both schemes against /rest/self and pin whichever authenticates.

    Cheaper and far more reliable than inferring from the token prefix -- one
    request per scheme, once per run.
    """
    global _AUTH_SCHEME
    token = os.environ["SNYK_TOKEN"].strip()
    if not token:
        sys.exit("SNYK_TOKEN is empty.")
    for scheme in ("token", "Bearer"):
        try:
            resp = requests.get(
                f"{API_BASE}/rest/self", params={"version": API_VERSION},
                headers={"Authorization": f"{scheme} {token}",
                         "Content-Type": "application/vnd.api+json"}, timeout=30)
        except requests.RequestException:
            continue
        if resp.ok:
            _AUTH_SCHEME = scheme
            return scheme
    return None


def snyk_headers(jsonapi=False):
    return {
        "Authorization": snyk_auth_value(os.environ["SNYK_TOKEN"]),
        "Content-Type": "application/vnd.api+json" if jsonapi else "application/json",
    }


def snyk_get(url, params=None, jsonapi=False):
    for _ in range(5):
        resp = requests.get(url, headers=snyk_headers(jsonapi), params=params, timeout=30)
        if resp.status_code == 429:
            time.sleep(int(resp.headers.get("Retry-After", 5)))
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError(f"Repeated 429 calling {url}")


def _resolve_next(next_link):
    if next_link.startswith("http"):
        return next_link
    if next_link.startswith("/rest/"):
        return API_BASE + next_link
    return API_BASE + "/rest" + next_link


def snyk_paginate(path, params):
    url = f"{API_BASE}{path}"
    while url:
        body = snyk_get(url, params=params, jsonapi=True)
        for item in body.get("data", []):
            yield item
        next_link = (body.get("links") or {}).get("next")
        if not next_link:
            break
        url = _resolve_next(next_link)
        params = None


def group_name(group_id):
    """Human-readable group name, so the report says what it acted on."""
    try:
        body = snyk_get(f"{API_BASE}/rest/groups/{group_id}",
                        {"version": API_VERSION}, jsonapi=True)
        return ((body.get("data") or {}).get("attributes") or {}).get("name") or group_id
    except requests.HTTPError:
        return group_id


def list_orgs_in_group(group_id):
    return list(snyk_paginate(f"/rest/groups/{group_id}/orgs",
                              {"version": API_VERSION, "limit": 100}))


def list_targets(org_id):
    # exclude_empty defaults to TRUE on this endpoint, which hides targets with
    # zero projects -- precisely the ones the coverage pass exists to find.
    # Without this flag the empty-target check can never fire.
    return list(snyk_paginate(f"/rest/orgs/{org_id}/targets",
                              {"version": API_VERSION, "limit": 100,
                               "exclude_empty": "false"}))


def list_projects(org_id):
    return list(snyk_paginate(f"/rest/orgs/{org_id}/projects",
                              {"version": API_VERSION, "limit": 100}))


def list_group_assets(group_id):
    """Repository assets Snyk has DISCOVERED across the whole group.

    This is a strictly larger set than the target list: Snyk discovers every
    repo its integration can see, but a target only exists once a repo has been
    imported. Scoping on targets therefore hides exactly the repos that still
    need onboarding.

    Quirks of this endpoint, all learned the hard way:
      * POST, not GET, and only at GROUP level -- the org-level path 404s.
      * Content-Type must be application/json, NOT application/vnd.api+json.
      * limit must be >= 10.
      * An empty body {} returns everything; a one-element "and" filter is
        rejected ("value must contain more then one element"), so repositories
        are filtered client-side on the top-level type instead.
    """
    assets, url = [], (f"{API_BASE}/rest/groups/{group_id}/assets/search"
                       f"?version={API_VERSION}&limit=100")
    while url:
        resp = requests.post(url, headers={
            "Authorization": snyk_auth_value(os.environ["SNYK_TOKEN"]),
            "Content-Type": "application/json"}, json={}, timeout=60)
        if not resp.ok:
            raise requests.HTTPError(f"assets search HTTP {resp.status_code}", response=resp)
        body = resp.json()
        assets += body.get("data", [])
        nxt = (body.get("links") or {}).get("next")
        url = _resolve_next(nxt) if nxt else None
    return [a for a in assets if a.get("type") == "repository"]


def asset_repo_name(asset):
    """owner/repo for a repository asset."""
    a = asset.get("attributes") or {}
    url = a.get("browse_url") or a.get("repository_url") or ""
    if "github.com/" in url:
        part = url.split("github.com/", 1)[1]
        part = part[:-4] if part.endswith(".git") else part
        bits = [b for b in part.split("/") if b]
        if len(bits) >= 2:
            return f"{bits[0]}/{bits[1]}"
    name = a.get("name") or ""
    return name if "/" in name else None


_integration_cache = {}


def get_github_integration_id(org_id):
    """Resolve an org's GitHub integration UUID, cached per org."""
    if org_id in _integration_cache:
        return _integration_cache[org_id]
    body = snyk_get(f"{API_BASE}/v1/org/{org_id}/integrations")
    for key in ("github", "github-enterprise", "github-cloud-app"):
        if body.get(key):
            _integration_cache[org_id] = body[key]
            return body[key]
    _integration_cache[org_id] = None
    return None


def import_target(org_id, integration_id, owner, name, branch):
    """Re-import a repo. Returns (ok, detail, already_existed)."""
    url = f"{API_BASE}/v1/org/{org_id}/integrations/{integration_id}/import"
    target = {"owner": owner, "name": name}
    if branch:
        target["branch"] = branch          # omitted -> Snyk uses the repo default
    payload = {"target": target}
    resp = requests.post(url, headers=snyk_headers(), json=payload, timeout=30)

    if resp.status_code in (200, 201):
        return True, resp.headers.get("Location", "queued"), False
    if resp.status_code == 409:
        # The target already exists. For an empty target this is still useful
        # (Snyk re-scans it), but it does NOT recreate a deleted webhook.
        return True, "target already exists (re-scan requested)", True
    if resp.status_code == 429:
        return False, "rate limited (retried next run)", False
    if resp.status_code in (401, 403):
        # Reads succeeding while imports 401 is a specific, common situation:
        # the token authenticates fine but either it lacks write permission,
        # or Snyk's own stored GitHub credentials have gone stale. The message
        # says "Invalid credentials" without saying WHOSE.
        return False, (
            f"HTTP {resp.status_code} {resp.text[:120]}\n"
            "          Reads work but imports do not. Two possible causes:\n"
            "          1) The token's role lacks import/write on this org "
            "(try a personal API token to compare).\n"
            "          2) Snyk's stored GitHub integration credentials are "
            "stale -- reconnect GitHub in Snyk Settings > Integrations.\n"
            "          Fastest check: import this repo from the Snyk UI. If the "
            "UI also fails, it is (2)."), False
    return False, f"HTTP {resp.status_code}: {resp.text[:200]}", False


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

def gh_headers():
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def gh_get(url, params=None):
    for _ in range(5):
        resp = requests.get(url, headers=gh_headers(), params=params, timeout=30)
        if resp.status_code in (403, 429) and resp.headers.get("X-RateLimit-Remaining") == "0":
            wait = max(int(resp.headers.get("X-RateLimit-Reset", 0)) - int(time.time()), 1)
            log(f"GitHub rate limited, sleeping {min(wait, 300)}s")
            time.sleep(min(wait, 300))
            continue
        return resp
    raise RuntimeError(f"Repeated rate limiting calling {url}")


def webhook_state(full_name):
    """'present' / 'missing' / 'unknown'.

    'unknown' is returned when we lack rights to read hooks, so a permissions
    gap can never masquerade as a missing webhook and trigger a pointless
    re-import.
    """
    resp = gh_get(f"{GITHUB_API_BASE}/repos/{full_name}/hooks", {"per_page": 100})
    if not resp.ok:
        return "unknown"
    for hook in resp.json():
        if "snyk.io" in (hook.get("config") or {}).get("url", ""):
            return "present" if hook.get("active") else "missing"
    return "missing"


def default_branch(full_name):
    """The repo's real default branch, or None if it cannot be determined.

    Returns None rather than guessing "main". Guessing is actively harmful:
    plenty of repos still default to "master", and importing the wrong branch
    either fails or creates a target pointing at a branch nobody uses. When
    this returns None the caller omits the field entirely and lets Snyk resolve
    the repo's own default.
    """
    resp = gh_get(f"{GITHUB_API_BASE}/repos/{full_name}")
    if resp.ok:
        return resp.json().get("default_branch") or None
    return None


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def load_state():
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        state = {}
    state.setdefault("repos", {})   # full_name -> {attempts, last_action, last_result}
    state.setdefault("last_run", None)
    return state


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, STATE_FILE)  # atomic: a crash mid-write cannot corrupt it


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

def build_inventory(quiet=False):
    """Every target in the group, with its project count, types and scan state.

    Scope comes from the ASSET inventory, not the target list. Snyk discovers
    every repo the integration can see; only some have ever been imported. An
    asset with no target is discovered-but-never-scanned, which is the main gap
    this script exists to close -- using targets as scope would make those
    repos invisible, because a target is created BY the import.

    Falls back to targets-only scope if the assets API is unavailable (older
    tenant, or a plan without asset discovery), so the script still runs.
    """
    inventory = {}
    failed_orgs = []

    gid = os.environ["SNYK_GROUP_ID"]
    if not quiet:
        head("Snyk")
        item("Group", f"{group_name(gid)}  {dim(gid)}")
    orgs = list_orgs_in_group(gid)

    for org in orgs:
        org_id = org["id"]
        org_name = (org.get("attributes") or {}).get("name") or org_id

        # A token can enumerate a group's orgs without being able to read
        # inside every one, and Snyk answers 404 (not 403) for an org it will
        # not show you. Skip it rather than losing the whole run.
        try:
            targets = list_targets(org_id)
            projects = list_projects(org_id)
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            hint = (" -- token cannot read this org; add the service account to it"
                    if code in (403, 404) else "")
            log_fail(f"{org_name}: SKIPPED HTTP {code}{hint}")
            failed_orgs.append(org_name)
            continue

        counts, types = {}, {}
        for p in projects:
            tid = ((p.get("relationships") or {}).get("target") or {}).get("data", {}).get("id")
            if tid:
                counts[tid] = counts.get(tid, 0) + 1
                types.setdefault(tid, set()).add((p.get("attributes") or {}).get("type", ""))

        # Scan state, keyed by repo name, from the targets that do exist.
        # `orig_name` preserves the real casing; the dict key is normalised.
        by_repo = {}
        for t in targets:
            a = t.get("attributes") or {}
            name = a.get("displayName") or a.get("display_name") or a.get("name")
            if name:
                by_repo[norm(name)] = {"target_id": t["id"],
                                       "orig_name": name,
                                       "project_count": counts.get(t["id"], 0),
                                       "types": types.get(t["id"], set())}

        # Scope is the target list. Snyk's model is target -> projects, where
        # each project is one scan of one manifest/surface (npm, sast,
        # dockerfile, terraformconfig, ...). A target with no projects was
        # imported but scanned nothing.
        for nm in {v["orig_name"] for v in by_repo.values()}:
            state = by_repo.get(norm(nm), {})
            ptypes = state.get("types") or set()
            inventory[norm(nm)] = {
                "full_name": state.get("orig_name") or nm,
                "org_id": org_id,
                "org_name": org_name,
                "target_id": state.get("target_id"),
                "project_count": state.get("project_count", 0),
                "imported": state.get("target_id") is not None,
                "has_sast": "sast" in ptypes,
                "has_sca": any(t and t != "sast" for t in ptypes),
                "types": sorted(t for t in ptypes if t),
            }

        if not quiet:
            item("Org", f"{org_name}  {dim(org_id)}")
            item("", f"{len(targets)} targets {dim('·')} {len(projects)} projects")

    # --- widen scope to everything Snyk has DISCOVERED, not just imported ---
    # A discovered repo with no target has never been onboarded; those are the
    # ones that matter most and the target list cannot show them.
    try:
        assets = list_group_assets(os.environ["SNYK_GROUP_ID"])
    except (requests.HTTPError, requests.RequestException) as e:
        assets = []
        if not quiet:
            log_warn(f"asset discovery unavailable ({e}); scope limited to imported targets")

    default_org = None
    org_ids = {v["org_id"] for v in inventory.values()}
    if len(org_ids) == 1:
        default_org = next(iter(org_ids))
    elif org_id_env := os.environ.get("SNYK_IMPORT_ORG_ID"):
        default_org = org_id_env

    discovered = 0
    for asset in assets:
        nm = asset_repo_name(asset)
        if not nm:
            continue
        key = norm(nm)
        if key in inventory:
            continue
        a = asset.get("attributes") or {}
        # Route to the org already holding repos from this GitHub owner; fall
        # back to the only org, or SNYK_IMPORT_ORG_ID when the group has several.
        owner = key.split("/")[0]
        same_owner = [v for k, v in inventory.items() if k.split("/")[0] == owner]
        org_id = same_owner[0]["org_id"] if same_owner else default_org
        if not org_id:
            if not quiet:
                log_warn(f"{nm}: discovered but no org to import into "
                         "(set SNYK_IMPORT_ORG_ID)")
            continue
        inventory[key] = {
            "full_name": nm,
            "org_id": org_id,
            "org_name": (same_owner[0]["org_name"] if same_owner else org_id[:8]),
            "target_id": None,
            "project_count": 0,
            "imported": False,
            "has_sast": False,
            "has_sca": False,
            "types": [],
            "branch": a.get("default_branch_name"),
            "archived": bool(a.get("archived")),
        }
        discovered += 1

    empty = sum(1 for v in inventory.values()
                if v.get("imported") and v["project_count"] == 0)
    never = sum(1 for v in inventory.values() if not v.get("imported", True))
    if not quiet:
        item("Discovered", f"{len(assets)} repo(s)" if assets else "n/a")
        item("In scope", f"{len(inventory)} repo(s)")
        item("Never imported", never, yellow if never else green)
        item("No projects", empty, yellow if empty else green)
    if failed_orgs:
        log_warn(f"{len(failed_orgs)} org(s) unreadable ({', '.join(failed_orgs)}); "
             "their repos are out of scope this run.")
    return inventory


def load_repo_list(path):
    """Read an explicit repo list from CSV or a plain text file.

    Used when you do not want the scope to come from the Snyk group -- either
    the group inventory is unavailable, or you want to act on a specific set.

    Accepted shapes (header row optional, column order free):

        repo,org_id,branch
        snyk-abhay/expo,48e8aebc-...,main
        snyk-abhay/WebKit

    or one "owner/name" per line in a .txt. Blank lines and '#' comments are
    ignored. Only `repo` is required; org_id falls back to --org, and branch
    falls back to the repo's GitHub default.
    """
    if not os.path.isfile(path):
        sys.exit(f"--repos file not found: {path}")

    rows, seen = [], set()
    with open(path, newline="") as f:
        sample = f.read(4096)
        f.seek(0)
        reader = csv.reader(f)
        header, cols = None, {}
        for lineno, fields in enumerate(reader, 1):
            fields = [x.strip() for x in fields]
            if not fields or not any(fields):
                continue
            if fields[0].startswith("#"):
                continue

            # First non-empty row is a header only if it names known columns.
            if header is None:
                lowered = [x.lower() for x in fields]
                if any(h in lowered for h in ("repo", "repository", "full_name", "name")):
                    header = lowered
                    for i, h in enumerate(header):
                        if h in ("repo", "repository", "full_name", "name"):
                            cols.setdefault("repo", i)
                        elif h in ("org", "org_id", "orgid", "snyk_org"):
                            cols.setdefault("org", i)
                        elif h in ("branch", "default_branch", "ref"):
                            cols.setdefault("branch", i)
                    continue
                header, cols = [], {"repo": 0}

            idx = cols.get("repo", 0)
            if idx >= len(fields) or not fields[idx]:
                continue
            repo = fields[idx]
            # Tolerate a clone URL or an owner/name@branch reference.
            if "github.com" in repo:
                repo = repo.split("github.com", 1)[1].lstrip("/:")
                repo = repo[:-4] if repo.endswith(".git") else repo
            branch = None
            if "@" in repo:
                repo, _, branch = repo.partition("@")
            if "/" not in repo:
                log_warn(f"{path}:{lineno}: skipping '{repo}' -- expected owner/name")
                continue

            org = fields[cols["org"]] if cols.get("org") is not None and cols["org"] < len(fields) else ""
            b = fields[cols["branch"]] if cols.get("branch") is not None and cols["branch"] < len(fields) else ""
            key = norm(repo)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"repo": repo, "org_id": org or None, "branch": branch or branch_or_none(b)})
    if not rows:
        sys.exit(f"--repos file had no usable rows: {path}")
    return rows


def branch_or_none(value):
    return value.strip() or None


def build_inventory_from_repos(repo_rows, default_org):
    """Inventory for an explicit repo list, with scan state pulled from Snyk.

    Scope is the file, not the group. A repo in the file with no Snyk target is
    reported as never imported -- which is the point: this path can onboard
    repos the group inventory would never surface.
    """
    org_ids = {r["org_id"] for r in repo_rows if r["org_id"]}
    if default_org:
        org_ids.add(default_org)
    if not org_ids:
        sys.exit("--repos needs a Snyk org: add an 'org_id' column, or pass --org "
                 "<org_id> (or set SNYK_IMPORT_ORG_ID).")

    head("Inventory")
    item("Source", f"{len(repo_rows)} repo(s) from file")

    state_by_repo, org_names = {}, {}
    for org_id in sorted(org_ids):
        try:
            targets = list_targets(org_id)
            projects = list_projects(org_id)
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            log_fail(f"org {org_id}: SKIPPED HTTP {code}")
            continue
        counts, types = {}, {}
        for p in projects:
            tid = ((p.get("relationships") or {}).get("target") or {}).get("data", {}).get("id")
            if tid:
                counts[tid] = counts.get(tid, 0) + 1
                types.setdefault(tid, set()).add((p.get("attributes") or {}).get("type", ""))
        org_names[org_id] = org_id[:8]
        for t in targets:
            a = t.get("attributes") or {}
            nm = a.get("displayName") or a.get("display_name") or a.get("name")
            if nm:
                state_by_repo[norm(nm)] = {
                    "target_id": t["id"], "orig_name": nm, "org_id": org_id,
                    "project_count": counts.get(t["id"], 0),
                    "types": types.get(t["id"], set()),
                }
        item(f"org {org_id[:8]}", f"{len(targets)} targets {dim('·')} {len(projects)} projects")

    inventory = {}
    for row in repo_rows:
        key = norm(row["repo"])
        st = state_by_repo.get(key, {})
        ptypes = st.get("types") or set()
        inventory[key] = {
            "full_name": st.get("orig_name") or row["repo"],
            "org_id": st.get("org_id") or row["org_id"] or default_org,
            "org_name": org_names.get(st.get("org_id") or row["org_id"] or default_org, ""),
            "target_id": st.get("target_id"),
            "project_count": st.get("project_count", 0),
            "imported": st.get("target_id") is not None,
            "has_sast": "sast" in ptypes,
            "has_sca": any(t and t != "sast" for t in ptypes),
            "types": sorted(t for t in ptypes if t),
            "branch": row["branch"],
        }

    never = sum(1 for v in inventory.values() if not v["imported"])
    empty = sum(1 for v in inventory.values() if v["imported"] and v["project_count"] == 0)
    item("In scope", f"{len(inventory)} repo(s)")
    item("Never imported", never, yellow if never else green)
    item("No projects", empty, yellow if empty else green)
    return inventory


def find_work(inventory):
    """Return [(full_name, info, [reasons])] for repos needing repair."""
    work, skipped = [], {}
    checked = 0

    for key, info in sorted(inventory.items()):
        full = info["full_name"]
        if excluded(full):
            skipped["excluded by EXCLUDE_REPOS"] = skipped.get("excluded by EXCLUDE_REPOS", 0) + 1
            continue
        if "/" not in full:
            # Non-GitHub or oddly-named target; webhook lookup is meaningless.
            skipped["not an owner/repo target"] = skipped.get("not an owner/repo target", 0) + 1
            continue
        if info.get("archived") and not INCLUDE_ARCHIVED:
            skipped["archived"] = skipped.get("archived", 0) + 1
            continue

        reasons = []
        if not info.get("imported"):
            reasons.append("never imported (discovered, no target)")
        elif info["project_count"] == 0:
            reasons.append("empty target (0 projects)")

        # A never-imported repo has no webhook by definition -- the import
        # creates it -- so skip the costly hook lookup for those.
        if CHECK_WEBHOOKS and info.get("imported"):
            state = webhook_state(full)
            info["webhook"] = state
            checked += 1
            if state == "missing":
                reasons.append("missing webhook")
            # 'unknown' is already reported in the webhook tally below; do not
            # double-count it as a skip reason.
        elif not info.get("imported"):
            info["webhook"] = "n/a (not imported)"
        else:
            info["webhook"] = "not checked"

        if reasons:
            work.append((full, info, reasons))

    if CHECK_WEBHOOKS:
        tally = {}
        for i in inventory.values():
            if i.get("imported"):
                tally[i.get("webhook", "not checked")] = \
                    tally.get(i.get("webhook", "not checked"), 0) + 1
        head("GitHub webhooks")
        item("Scanned", f"{checked} repo(s) via {GITHUB_API_BASE.split('//')[-1]}")
        item("Present", tally.get("present", 0), green)
        item("Missing", tally.get("missing", 0), yellow if tally.get("missing") else green)
        if tally.get("unknown"):
            item("Unknown", tally["unknown"], yellow)
            item("", dim("no admin rights on those repos - cannot tell"))
    for reason, count in sorted(skipped.items(), key=lambda kv: -kv[1]):
        item("Skipped", f"{count} {dim('- ' + reason)}", yellow)
    return work


# ---------------------------------------------------------------------------

def coverage_label(info):
    """SAST / SCA mix for one repo, in the CSV's terms."""
    if not info.get("imported"):
        return "not imported"
    if info.get("project_count", 0) == 0:
        return "not scanned (empty target)"
    if info.get("has_sca") and info.get("has_sast"):
        return "SCA + SAST"
    if info.get("has_sca"):
        return "SCA only"
    if info.get("has_sast"):
        return "SAST only"
    return "unknown"


def write_csv(inventory, path):
    """One row per in-scope repo: the inventory a human can actually read."""
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["repo", "org", "webhook", "scanned", "project_count",
                    "coverage", "has_sca", "has_sast", "project_types"])
        for _, i in sorted(inventory.items()):
            w.writerow([
                i["full_name"], i["org_name"],
                i.get("webhook", "not checked"),
                "yes" if i.get("project_count", 0) > 0 else "no",
                i.get("project_count", 0),
                coverage_label(i),
                "yes" if i.get("has_sca") else "no",
                "yes" if i.get("has_sast") else "no",
                ";".join(i.get("types", [])),
            ])
    log(f"{cyan('→')} report  {path}  {dim(f'({len(inventory)} repos)')}")


def verify_previous_run(state, inventory):
    """Did last run's imports actually take effect?

    Imports are async, so the honest place to check is the START of the next
    run rather than seconds after firing them. Repos are compared against the
    state recorded when they were acted on.
    """
    pending = {k: v for k, v in state.get("repos", {}).items() if v.get("pending_verify")}
    if not pending:
        return
    fixed_scan = fixed_hook = still_broken = 0
    for key, rec in pending.items():
        info = inventory.get(key)
        if not info:
            continue
        got_projects = info.get("project_count", 0) > 0
        got_hook = info.get("webhook") == "present"
        was = rec.get("last_reasons", [])
        ok = True
        if any("empty target" in r or "never imported" in r for r in was):
            if got_projects:
                fixed_scan += 1
            else:
                ok = False
        if any("missing webhook" in r for r in was):
            if got_hook:
                fixed_hook += 1
            else:
                ok = False
        if ok:
            rec["pending_verify"] = False
            rec["verified_at"] = datetime.now(timezone.utc).isoformat()
            # Clear the counter: a repo that is now healthy must not keep
            # showing up in the "needs a human" note forever.
            rec["attempts"] = 0
        else:
            still_broken += 1
    head("Verification of previous run")
    item("Acted on", f"{len(pending)} repo(s)")
    item("Now scanned", fixed_scan, green if fixed_scan else None)
    item("Webhook created", fixed_hook, green if fixed_hook else None)
    item("Still broken", still_broken, red if still_broken else green)


def delete_target(org_id, target_id):
    """Delete a Snyk target so it can be imported fresh. DESTRUCTIVE.

    Needed because a re-import cannot recreate a webhook that was removed on
    the GitHub side: Snyk returns 409 (target exists) and changes nothing. The
    only way to get the webhook back through the API is to delete the target
    and import it fresh.

    What is lost, permanently:
      * issue history and first-seen dates
      * project-level ignores and policies
      * project IDs, breaking any external references to them

    Returns (ok, detail).
    """
    url = f"{API_BASE}/rest/orgs/{org_id}/targets/{target_id}?version={API_VERSION}"
    resp = requests.delete(url, headers=snyk_headers(jsonapi=True), timeout=30)
    if resp.status_code in (200, 202, 204):
        return True, "target deleted"
    if resp.status_code == 404:
        return True, "target already gone"
    return False, f"delete failed HTTP {resp.status_code}: {resp.text[:120]}"


def poll_import_job(url, timeout=IMPORT_JOB_TIMEOUT):
    """Follow an import job to completion.

    The v1 import endpoint returns 201 with a Location header pointing at an
    async job. Polling it is what makes in-run verification honest -- otherwise
    we would check for projects before Snyk has created any and wrongly report
    failure.

    Returns (status, detail): status is 'complete' / 'failed' / 'timeout'.
    """
    if not url or not url.startswith("http"):
        return "unknown", "no job url returned"
    deadline = time.time() + timeout
    last = "pending"
    while time.time() < deadline:
        try:
            resp = requests.get(url, headers=snyk_headers(), timeout=30)
        except requests.RequestException as e:
            return "unknown", f"job poll error: {e}"
        if not resp.ok:
            return "unknown", f"job poll HTTP {resp.status_code}"
        body = resp.json()
        last = (body.get("status") or "pending").lower()
        if last in ("complete", "completed", "success"):
            logs = body.get("logs") or []
            made = sum(1 for l in logs if str(l.get("status", "")).lower()
                       in ("created", "complete", "success"))
            return "complete", f"{made} project(s) created" if made else "no projects created"
        if last in ("failed", "error"):
            logs = body.get("logs") or []
            why = next((l.get("name") or str(l) for l in logs), "")
            return "failed", f"import job failed {why}"[:160]
        time.sleep(IMPORT_POLL_INTERVAL)
    return "timeout", f"still '{last}' after {timeout}s (may finish later)"


def report_coverage(inventory):
    """Which scan types each repo actually has.

    Split out because "imported" and "covered" are different questions: a repo
    can be imported, webhooked and still have no SAST project at all.
    """
    both, sca, sast, none = [], [], [], []
    for _, i in sorted(inventory.items()):
        if not i.get("imported") or i.get("project_count", 0) == 0:
            none.append(i["full_name"])
        elif i.get("has_sca") and i.get("has_sast"):
            both.append(i["full_name"])
        elif i.get("has_sca"):
            sca.append(i["full_name"])
        elif i.get("has_sast"):
            sast.append(i["full_name"])

    head("Coverage")
    item("SCA + SAST", len(both), green)
    item("SCA only", f"{len(sca)} {dim('- no Snyk Code project')}",
         yellow if sca else None)
    for r in sca[:LIST_LIMIT]:
        print(f"        {dim('-')} {r}", file=sys.stderr)
    item("SAST only", f"{len(sast)} {dim('- no Open Source project')}",
         yellow if sast else None)
    for r in sast[:LIST_LIMIT]:
        print(f"        {dim('-')} {r}", file=sys.stderr)
    item("Not scanned", len(none), yellow if none else green)
    for r in none[:LIST_LIMIT]:
        print(f"        {dim('-')} {r}", file=sys.stderr)


def classify_work(work):
    """Split the work list into the buckets the operator chooses between."""
    buckets = {"webhook": [], "unscanned": []}
    for item in work:
        _, _, reasons = item
        if any("missing webhook" in r for r in reasons):
            buckets["webhook"].append(item)
        else:
            buckets["unscanned"].append(item)
    return buckets


def choose_scope(buckets, preset):
    """Decide which buckets to act on: flag, or prompt when interactive.

    Never prompts when stdin is not a TTY -- a cron run must not block forever
    waiting for an answer nobody is there to give.
    """
    n_hook, n_scan = len(buckets["webhook"]), len(buckets["unscanned"])
    head("Action required")

    def listing(label, items, note):
        item(label, f"{len(items)} repo(s) {dim(note)}", yellow if items else None)
        # Name them. A bare count tells you something is wrong but not what,
        # and these lists drive a decision the operator is about to make.
        for full, info, _ in items[:LIST_LIMIT]:
            proj = info.get("project_count", 0)
            print(f"        {dim('-')} {full} {dim(f'({proj} projects)')}",
                  file=sys.stderr)
        if len(items) > LIST_LIMIT:
            print(f"        {dim(f'... and {len(items) - LIST_LIMIT} more')}",
                  file=sys.stderr)

    listing("[1] webhook", buckets["webhook"], "on Snyk, but no webhook")
    listing("[2] unscanned", buckets["unscanned"], "no target, or target with 0 projects")
    item("[3] both", f"{n_hook + n_scan} repo(s)")

    if preset:
        log(f"Scope: {preset} (from --scope)")
        return preset
    if not sys.stdin.isatty():
        log("Scope: both (non-interactive; use --scope to choose)")
        return "both"
    try:
        ans = input("  Import which? [1/2/3, or n to cancel] (default 3): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return "none"
    return {"1": "webhook", "2": "unscanned", "3": "both",
            "": "both", "n": "none"}.get(ans, "both")


def select_batch(buckets, scope):
    if scope == "none":
        return []
    if scope == "webhook":
        return buckets["webhook"]
    if scope == "unscanned":
        return buckets["unscanned"]
    return buckets["webhook"] + buckets["unscanned"]


def run_once(apply_changes, scope=None):
    """Stage 1 check -> report -> choose -> import one by one -> verify -> CSV.

    The CSV is written LAST, deliberately: written before the imports it would
    describe a state that is already stale by the time the run finishes.
    """
    state = load_state()

    # --- Stage 1: what exists, and what is broken (incl. webhook check) ---
    inventory = build_inventory()
    if not inventory:
        log("Inventory is empty -- nothing in scope. Check the token's group access.")
        return 1

    work = find_work(inventory)
    report_coverage(inventory)
    verify_previous_run(state, inventory)

    if not work:
        head("Result")
        log_ok("Nothing to repair - every repo is scanned and has a webhook.")
        write_csv(inventory, CSV_FILE)
        state["last_run"] = datetime.now(timezone.utc).isoformat()
        save_state(state)
        return 0

    # --- Stage 2: report the split and pick what to act on ---
    buckets = classify_work(work)
    chosen = select_batch(buckets, choose_scope(buckets, scope))

    if not chosen:
        log("Nothing selected -- writing report only.")
        write_csv(inventory, CSV_FILE)
        return 0

    if len(chosen) > MAX_ACTIONS_PER_RUN:
        log(f"Acting on {MAX_ACTIONS_PER_RUN} of {len(chosen)} "
            f"(MAX_ACTIONS_PER_RUN); the rest follow next run")
        chosen = chosen[:MAX_ACTIONS_PER_RUN]

    if not apply_changes:
        log(f"DRY RUN -- {len(chosen)} repo(s) would be imported. Re-run with --apply:")
        for full, info, reasons in chosen:
            print(f"  would import  {full}  [{info['org_name']}]  -- {', '.join(reasons)}")
        write_csv(inventory, CSV_FILE)
        return 0

    # --- Stage 3: import one by one, following each job to completion ---
    ok_count = fail_count = 0
    acted = []
    needs_manual = []

    # A missing webhook can only be restored by deleting the target and
    # importing fresh -- a plain re-import returns 409 and changes nothing.
    # Only imported repos qualify; a never-imported repo has no target.
    recreate_keys = {norm(f) for f, info, reasons in chosen
                     if info.get("target_id")
                     and any("missing webhook" in r for r in reasons)}

    for i, (full, info, reasons) in enumerate(chosen, 1):
        integration_id = get_github_integration_id(info["org_id"])
        if not integration_id:
            log(f"[{i}/{len(chosen)}] SKIP     {full} -- no GitHub integration on "
                f"org {info['org_name']}")
            continue

        if norm(full) in recreate_keys:
            gone, why = delete_target(info["org_id"], info["target_id"])
            if gone:
                log(f"[{i}/{len(chosen)}] {full} {dim('- re-importing')}")
            else:
                # Still surfaced: if the delete failed the import will 409 and
                # the webhook will not come back, so this must not be silent.
                log_fail(f"[{i}/{len(chosen)}] {full}: {why}")

        owner, _, name = full.partition("/")
        # The asset already carries the real default branch; only fall back to
        # a GitHub lookup when it does not.
        branch = info.get("branch") or default_branch(full)
        if not branch:
            log_warn(f"{full}: could not read default branch from GitHub; "
                     "letting Snyk resolve it")
        ok, detail, existed = import_target(info["org_id"], integration_id,
                                            owner, name, branch)

        rec = state["repos"].setdefault(norm(full), {"attempts": 0})
        rec["attempts"] += 1
        rec["last_action"] = datetime.now(timezone.utc).isoformat()
        rec["last_reasons"] = reasons

        if ok:
            # Follow the async job rather than assuming it worked.
            job_status, job_detail = poll_import_job(detail)
            rec["last_result"] = f"{job_status}: {job_detail}"
            if job_status in ("complete", "unknown", "timeout"):
                ok_count += 1
                log_ok(f"[{i}/{len(chosen)}] {full} {dim('-')} {job_detail}")
            else:
                fail_count += 1
                log_fail(f"[{i}/{len(chosen)}] {full} {dim('-')} {job_detail}")
            acted.append((full, info))
            # 409 means the target already existed, so the re-import re-scans
            # but cannot recreate a webhook deleted on the GitHub side.
            if existed and any("missing webhook" in r for r in reasons):
                needs_manual.append(full)
        else:
            fail_count += 1
            rec["last_result"] = detail
            log_fail(f"[{i}/{len(chosen)}] {full} {dim('-')} {detail}")

        rec["pending_verify"] = True
        save_state(state)  # after each repo, so a crash does not lose progress
        if i < len(chosen):
            time.sleep(IMPORT_DELAY)

    head("Result")
    item("Succeeded", ok_count, green if ok_count else None)
    item("Failed", fail_count, red if fail_count else green)

    # --- Stage 4: re-check the repos we touched, so the CSV is current ---
    if acted:
        head("Re-check")
        item("Repos", f"{len(acted)}")
        fresh = build_inventory(quiet=True)
        for full, _ in acted:
            key = norm(full)
            new_info = fresh.get(key)
            if not new_info:
                continue
            if CHECK_WEBHOOKS and new_info.get("imported"):
                new_info["webhook"] = webhook_state(new_info["full_name"])
            inventory[key] = new_info
            rec = state["repos"].get(key, {})
            scanned = new_info.get("project_count", 0) > 0
            hook = new_info.get("webhook", "not checked")
            hook_s = green(hook) if hook == "present" else yellow(hook)
            item(full.split("/")[-1][:16],
                 f"projects={new_info.get('project_count', 0)} {dim('·')} webhook={hook_s}")
            if scanned and hook in ("present", "n/a (not imported)", "unknown"):
                rec["pending_verify"] = False
                rec["attempts"] = 0
            elif hook == "missing" and full not in needs_manual:
                # Import ran but the webhook still is not there.
                needs_manual.append(full)
        save_state(state)

    if needs_manual:
        log_warn(f"{len(needs_manual)} repo(s) STILL have no webhook after a "
                 "delete-and-re-import. The webhook can lag the import job, so "
                 "re-check on the next run before intervening by hand:")
        for full in needs_manual[:20]:
            log(f"    {full}")
        if len(needs_manual) > 20:
            log(f"    ... and {len(needs_manual) - 20} more")

    # --- Stage 5: CSV last, reflecting the post-import state ---
    write_csv(inventory, CSV_FILE)

    state["last_run"] = datetime.now(timezone.utc).isoformat()
    save_state(state)

    still_broken = {norm(f) for f, _, _ in work}
    stuck = [r for r, v in state["repos"].items()
             if v.get("attempts", 0) >= ATTENTION_THRESHOLD and r in still_broken]
    if stuck:
        log(f"NOTE: {len(stuck)} repo(s) retried {ATTENTION_THRESHOLD}+ times and still "
            "broken -- likely nothing scannable, or an import that cannot succeed:")
        for r in stuck[:10]:
            log(f"    {r}")

    return 1 if fail_count else 0


def preflight():
    """Validate credentials before doing any work.

    Without this, a bad token surfaces as a raw traceback from deep inside
    pagination -- useless in a cron log at 3am. Token and group are checked
    separately, because 401 and 404 here mean very different things.
    """
    token = os.environ["SNYK_TOKEN"].strip()
    if not detect_auth_scheme():
        sys.exit(
            f"Snyk rejected SNYK_TOKEN with BOTH auth schemes at {API_BASE}.\n"
            f"  Token seen: starts '{token[:10]}', length {len(token)}.\n"
            "  * Truncation is the most common cause. Snyk PATs (snyk_uat.*) are\n"
            "    long JWTs and the copy dialog visually clips them -- use the Copy\n"
            "    button, never select-and-copy from the box.\n"
            "  * Wrong region: tokens are region-scoped. Check SNYK_API_BASE has\n"
            "    no /v1 suffix and matches your account's region.\n"
            "  * Re-export cleanly:  export SNYK_TOKEN='<paste>'  (quoted, no newline)\n"
            "  * An OAuth CLI login (`snyk auth`) does NOT set SNYK_TOKEN.")

    if len(token) != 36:
        # Reads will still work, but the legacy v1 import endpoint rejects
        # snyk_uat./snyk_sat. tokens with a misleading "Invalid credentials".
        # Warn now rather than after a full inventory pass.
        log("WARNING: SNYK_TOKEN is not a classic 36-char UUID. Reads will work, "
            "but IMPORTS will likely fail with 401 'Invalid credentials'. Use the "
            "Auth Token from Account Settings > General.")

    group_id = os.environ["SNYK_GROUP_ID"]
    try:
        snyk_get(f"{API_BASE}/rest/groups/{group_id}", {"version": API_VERSION}, jsonapi=True)
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "?"
        if code in (401, 403, 404):
            sys.exit(
                f"The token is valid, but cannot read group {group_id} (HTTP {code}).\n"
                "  Snyk answers 404 for a group it will not show you, so this means\n"
                "  'wrong group id' or 'no access' -- not necessarily 'does not exist'.\n"
                "  List the groups this token CAN see:\n"
                f"    curl -s -H \"Authorization: token $SNYK_TOKEN\" \\\n"
                f"      \"{API_BASE}/rest/groups?version={API_VERSION}&limit=100\"")
        raise


def parse_interval(text):
    """'6h' -> 21600. Accepts plain seconds too."""
    text = text.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text and text[-1] in units:
        return int(float(text[:-1]) * units[text[-1]])
    return int(text)


def main():
    ap = argparse.ArgumentParser(
        description="Repair Snyk onboarding (webhooks and empty targets) for repos "
                    "already in the Snyk group.")
    ap.add_argument("--apply", action="store_true",
                    help="actually re-import; without this the run is a dry run")
    ap.add_argument("--schedule", metavar="INTERVAL",
                    help="loop forever at this interval, e.g. 6h. Prefer cron where available.")
    ap.add_argument("--scope", choices=["webhook", "unscanned", "both", "none"],
                    help="what to import without prompting: 'webhook' (imported but no "
                         "webhook), 'unscanned' (no target or 0 projects), 'both'. "
                         "Required for cron; without it an interactive run prompts and a "
                         "non-interactive run defaults to 'both'.")
    args = ap.parse_args()

    for var in ("SNYK_TOKEN", "SNYK_GROUP_ID"):
        if not os.environ.get(var):
            sys.exit(f"Missing required environment variable: {var}. See the setup notes in this file.")
    if CHECK_WEBHOOKS and not GITHUB_TOKEN:
        sys.exit("GITHUB_TOKEN is required for the webhook pass. "
                 "Set it, or set CHECK_WEBHOOKS=0 to check empty targets only.")

    preflight()

    if not args.schedule:
        sys.exit(run_once(args.apply, args.scope))

    interval = parse_interval(args.schedule)
    log(f"Scheduler started: every {args.schedule} ({interval}s). "
        f"{'APPLY' if args.apply else 'DRY RUN'} mode.")
    while True:
        try:
            run_once(args.apply, args.scope or 'both')
        except Exception as e:  # a bad run must not kill the scheduler
            log(f"Run failed: {type(e).__name__}: {e}")
        log(f"Sleeping {interval}s until next run")
        time.sleep(interval)


if __name__ == "__main__":
    main()
