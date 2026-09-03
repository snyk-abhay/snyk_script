#!/usr/bin/env python3
"""
Snyk Empty Target Cleanup

Finds targets that exist in Snyk but hold ZERO projects -- the residue of a
failed or abandoned import -- and lets you delete them interactively.

    Group  ->  Org  ->  list of empty targets  ->  pick  ->  delete

WHAT COUNTS AS EMPTY
--------------------
A target with no project attached, of any type and any status. A repo that
imported cleanly always has at least one project; a target with none is a repo
Snyk was told to watch and then never scanned. It contributes nothing but noise
to the UI and to target counts.

Deliberately NOT treated as empty:
  * targets whose only projects are deactivated -- those still carry history,
    and the count here includes inactive projects precisely so they survive.
  * anything the pre-delete re-check finds projects for. Every target is
    re-queried on its own immediately before deletion, so a target that gained
    a project while you were reading the list is skipped, not deleted.

Freshly created targets are flagged, not hidden: a target minutes old is
usually an import still in flight rather than a failed one. They are listed
with their age and a warning, and excluded from `all` selections unless you
pass --include-recent.

SAFETY
------
  * Dry run by default. Nothing is deleted without --apply.
  * Interactive runs require typing DELETE in full to confirm.
  * A cap (--max-deletes, default 100) bounds the blast radius of a misfire.
  * Every deletion is logged as it happens, with its target id.

Deleting a target is PERMANENT. For an empty target there is no issue history
to lose, which is exactly why this is a safe class of cleanup -- but a target
that turns out not to be empty would lose ignores, first-seen dates and project
ids, hence the re-check.

SETUP
-----
1. A Snyk token that can read the group and delete targets in the orgs you
   pick (a Group service account with admin is cleanest).
2. Match the API host to your region. app.us.snyk.io -> api.us.snyk.io,
   likewise api.eu.snyk.io / api.au.snyk.io. The wrong region returns 401.
3. pip install requests
4. export SNYK_TOKEN=xxxxxxxx
   export SNYK_API_BASE=https://api.us.snyk.io   # default: https://api.snyk.io
   export SNYK_GROUP_ID=xxxxxxxx                 # optional, skips the picker

USAGE
-----
  python3 snyk_delete_empty_targets.py                    # pick, preview only
  python3 snyk_delete_empty_targets.py --apply            # pick, then delete
  python3 snyk_delete_empty_targets.py --group <id> --org <name> --apply
  python3 snyk_delete_empty_targets.py --all-orgs --csv empty.csv
  python3 snyk_delete_empty_targets.py --filter 'legacy-*' --apply

  # unattended: deletes every empty target found, no prompts
  python3 snyk_delete_empty_targets.py --group <id> --all-orgs --apply --yes
"""

import argparse
import csv
import fnmatch
import os
import sys
import time
from datetime import datetime, timezone

import requests

API_BASE = os.environ.get("SNYK_API_BASE", "https://api.snyk.io").rstrip("/")
API_VERSION = "2024-10-15"

# A target younger than this is probably an import still running, not a failed
# one. Such targets are shown but kept out of bulk selections by default.
RECENT_HOURS = float(os.environ.get("RECENT_HOURS", "24"))

# Bounds the damage of a mistake. Deliberately low: this is a cleanup task, not
# a migration, and nobody legitimately deletes thousands of targets in one go
# without thinking about it first.
DEFAULT_MAX_DELETES = int(os.environ.get("MAX_DELETES", "100"))

DELETE_DELAY = float(os.environ.get("DELETE_DELAY", "0.2"))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
# Colour only on a terminal, and honour NO_COLOR, so redirected logs stay clean.
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


def log_ok(msg):   log(f"{green('/')} {msg}")
def log_warn(msg): log(f"{yellow('!')} {yellow(msg)}")
def log_fail(msg): log(f"{red('x')} {msg}")


TOTAL_STEPS = 5
_step_no = 0


def step(title):
    """Numbered section header, so a run reads as stages rather than a wall.

      1 Group      which group to work in
      2 Org        which org(s) inside it
      3 Scan       Snyk API: targets + projects, matched up
      4 Select     which empty targets to remove
      5 Delete     the destructive part, or the dry-run preview
    """
    global _step_no
    _step_no += 1
    print(f"\n{bold(cyan(f'> STEP {_step_no}/{TOTAL_STEPS}  {title}'))}",
          file=sys.stderr, flush=True)


def item(label, value, style=None):
    styled = style(str(value)) if style else str(value)
    print(f"   {label:<16} {styled}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Snyk API
# ---------------------------------------------------------------------------

_AUTH_SCHEME = None


def snyk_auth_value(token, scheme=None):
    """Snyk accepts two auth schemes and the token prefix does not reliably say
    which -- 'Bearer' for newer tokens, 'token' for classic UUID keys. Sending
    the wrong one is a 401 indistinguishable from a bad token, so detect_auth_scheme()
    probes both once and pins the answer instead of guessing per request.
    """
    scheme = scheme or _AUTH_SCHEME or "token"
    return f"{scheme} {(token or '').strip()}"


def detect_auth_scheme():
    global _AUTH_SCHEME
    token = os.environ.get("SNYK_TOKEN", "").strip()
    if not token:
        sys.exit("SNYK_TOKEN is not set (or is empty). See the setup notes at the "
                 "top of this file.")
    for scheme in ("token", "Bearer"):
        try:
            resp = requests.get(f"{API_BASE}/rest/self", params={"version": API_VERSION},
                                headers={"Authorization": f"{scheme} {token}",
                                         "Content-Type": "application/vnd.api+json"},
                                timeout=30)
        except requests.RequestException as e:
            sys.exit(f"Cannot reach {API_BASE}: {e}")
        if resp.ok:
            _AUTH_SCHEME = scheme
            return scheme
    sys.exit(f"SNYK_TOKEN was rejected by {API_BASE} under both auth schemes.\n"
             "  * wrong region? app.us.snyk.io means SNYK_API_BASE=https://api.us.snyk.io\n"
             "  * expired or revoked token?")


def headers():
    return {
        "Authorization": snyk_auth_value(os.environ["SNYK_TOKEN"]),
        "Content-Type": "application/vnd.api+json",
    }


def snyk_get(url, params=None):
    for _ in range(5):
        resp = requests.get(url, headers=headers(), params=params, timeout=30)
        if resp.status_code == 429:
            time.sleep(int(resp.headers.get("Retry-After", 5)))
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError(f"Repeated 429 (rate limited) calling {url}")


def _resolve_next(next_link):
    if next_link.startswith("http"):
        return next_link
    if next_link.startswith("/rest/"):
        return API_BASE + next_link
    return API_BASE + "/rest" + next_link  # docs emit relative links without /rest


def paginate(path, params):
    url = f"{API_BASE}{path}"
    while url:
        body = snyk_get(url, params=params)
        for row in body.get("data", []):
            yield row
        next_link = (body.get("links") or {}).get("next")
        if not next_link:
            break
        url = _resolve_next(next_link)
        params = None  # the next link already carries the query string


def attr(d, *keys, default=""):
    """First non-empty of several possible key spellings."""
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def list_groups():
    return list(paginate("/rest/groups", {"version": API_VERSION, "limit": 100}))


def list_orgs_in_group(group_id):
    return list(paginate(f"/rest/groups/{group_id}/orgs",
                         {"version": API_VERSION, "limit": 100}))


def list_targets(org_id):
    # exclude_empty defaults to TRUE here, which hides targets with zero
    # projects -- the only thing this script is looking for. Without the flag
    # the scan always finds nothing.
    return list(paginate(f"/rest/orgs/{org_id}/targets",
                         {"version": API_VERSION, "limit": 100,
                          "exclude_empty": "false"}))


def list_projects(org_id):
    return list(paginate(f"/rest/orgs/{org_id}/projects",
                         {"version": API_VERSION, "limit": 100}))


def count_projects_for_target(org_id, target_id):
    """Project count for one target, asked fresh.

    The bulk listing can be minutes old by the time a human has read the table
    and confirmed, and an import finishing in that window would turn a listed
    'empty' target into a real one. Re-asking per target immediately before the
    delete closes that window.

    Returns -1 if the count cannot be established, which callers treat as
    "do not delete" -- an unknown is never assumed to be empty.
    """
    try:
        body = snyk_get(f"{API_BASE}/rest/orgs/{org_id}/projects",
                        {"version": API_VERSION, "limit": 10, "target_id": target_id})
    except (requests.HTTPError, requests.RequestException, RuntimeError) as e:
        log_warn(f"re-check failed for {target_id}: {e}")
        return -1
    return len(body.get("data", []))


def delete_target(org_id, target_id):
    """DELETE one target. Returns (ok, detail)."""
    url = f"{API_BASE}/rest/orgs/{org_id}/targets/{target_id}"
    for _ in range(5):
        resp = requests.delete(url, headers=headers(),
                               params={"version": API_VERSION}, timeout=30)
        if resp.status_code == 429:
            time.sleep(int(resp.headers.get("Retry-After", 5)))
            continue
        if resp.status_code in (200, 202, 204):
            return True, "deleted"
        if resp.status_code == 404:
            return True, "already gone"
        if resp.status_code in (401, 403):
            return False, (f"HTTP {resp.status_code} -- the token can read this org "
                           "but not delete in it; it needs org admin")
        return False, f"HTTP {resp.status_code}: {resp.text[:140]}"
    return False, "rate limited five times in a row"


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def norm(name):
    return (name or "").strip().lower()


def parse_ts(value):
    """Snyk timestamps are RFC3339 with a trailing Z, which fromisoformat only
    learned to parse in 3.11. Swap it for +00:00 so older interpreters work too.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def age_hours(created):
    if created is None:
        return None
    return (datetime.now(timezone.utc) - created).total_seconds() / 3600


def fmt_age(hours):
    if hours is None:
        return "?"
    if hours < 48:
        return f"{hours:.0f}h"
    return f"{hours / 24:.0f}d"


def scan_org(org_id, org_name, name_filter, excludes):
    """Every target in one org that has no projects at all.

    Both listings are pulled in full and joined locally rather than asking per
    target: one org with 2,000 targets is 20 target pages plus 20 project pages,
    against 2,000 individual calls the other way.
    """
    targets = list_targets(org_id)
    projects = list_projects(org_id)

    counts = {}
    for p in projects:
        tid = (((p.get("relationships") or {}).get("target") or {})
               .get("data") or {}).get("id")
        if tid:
            counts[tid] = counts.get(tid, 0) + 1

    item(f"{org_name}", f"{len(targets)} target(s), {len(projects)} project(s)")

    found = []
    for t in targets:
        tid = t.get("id")
        if counts.get(tid):
            continue
        a = t.get("attributes", {})
        name = attr(a, "display_name", "displayName", "name", default=tid)
        if name_filter and not fnmatch.fnmatch(norm(name), norm(name_filter)):
            continue
        if any(fnmatch.fnmatch(norm(name), pat) for pat in excludes):
            continue
        created = parse_ts(attr(a, "created_at", "createdAt"))
        found.append({
            "org_id": org_id,
            "org_name": org_name,
            "target_id": tid,
            "name": name,
            "origin": attr(a, "origin", default="?"),
            "url": attr(a, "url", "remote_url", "remoteUrl"),
            "created": created,
            "age_h": age_hours(created),
        })

    found.sort(key=lambda r: norm(r["name"]))
    return found


# ---------------------------------------------------------------------------
# Pickers
# ---------------------------------------------------------------------------

def ask(prompt, default=""):
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return default


def choose_group(preset):
    """Which group. Returns (group_id, group_name) or exits."""
    step("Group")
    if preset:
        item("Group", preset, cyan)
        return preset, preset

    try:
        groups = list_groups()
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "?"
        sys.exit(f"Cannot list groups (HTTP {code}). An org-scoped token cannot "
                 "enumerate groups -- pass --group <id> or set SNYK_GROUP_ID.")

    if not groups:
        sys.exit("This token can see no groups. Pass --group <id> explicitly.")

    rows = [(g["id"], attr(g.get("attributes", {}), "name", default=g["id"])) for g in groups]
    rows.sort(key=lambda r: norm(r[1]))

    if len(rows) == 1:
        item("Group", f"{rows[0][1]}  {dim(rows[0][0])}", cyan)
        return rows[0]

    for n, (gid, gname) in enumerate(rows, 1):
        item(f"[{n}] {gname}", dim(gid))

    if not sys.stdin.isatty():
        sys.exit("Several groups are visible and this is not an interactive "
                 "terminal. Pass --group <id>.")

    ans = ask(f"  Which group? [1-{len(rows)}, or n to cancel]: ")
    if not ans.isdigit() or not 1 <= int(ans) <= len(rows):
        sys.exit("Cancelled.")
    return rows[int(ans) - 1]


def choose_orgs(group_id, preset, all_orgs):
    """Which org(s) inside the group. Returns a list of (org_id, org_name).

    The org is picked BEFORE scanning, not after: scanning every org in a large
    group to build the menu would be the slowest part of the run, and would be
    thrown away the moment one org is chosen.
    """
    step("Org")
    try:
        orgs = list_orgs_in_group(group_id)
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "?"
        sys.exit(f"Cannot list orgs in group {group_id} (HTTP {code}). Check the "
                 "group id and that the token has group-level read.")

    rows = [(o["id"], attr(o.get("attributes", {}), "name", "slug", default=o["id"]))
            for o in orgs]
    rows.sort(key=lambda r: norm(r[1]))
    if not rows:
        sys.exit("No orgs in this group are visible to the token.")

    if preset:
        want = norm(preset)
        hit = [r for r in rows if norm(r[1]) == want or r[0] == preset]
        if not hit:
            sys.exit(f"--org {preset!r} matched none of: "
                     + ", ".join(name for _, name in rows))
        item("Org", f"{hit[0][1]}  {dim(hit[0][0])}", cyan)
        return hit

    if all_orgs:
        item("Org", f"all {len(rows)} org(s) in the group", cyan)
        return rows

    for n, (oid, oname) in enumerate(rows, 1):
        item(f"[{n}] {oname}", dim(oid))
    all_n = len(rows) + 1
    item(f"[{all_n}] all orgs", f"{len(rows)} org(s)")

    if not sys.stdin.isatty():
        sys.exit("Not an interactive terminal. Pass --org <name|id> or --all-orgs.")

    ans = ask(f"  Which org? [1-{all_n}, or n to cancel]: ").lower()
    if ans == "n" or not ans.isdigit():
        sys.exit("Cancelled.")
    n = int(ans)
    if 1 <= n <= len(rows):
        return [rows[n - 1]]
    if n == all_n:
        return rows
    sys.exit("Cancelled.")


def show_table(found, multi_org):
    """The report. One line per empty target, numbered for selection."""
    # Widths follow the data but never shrink below their own headings,
    # otherwise a run where every repo name is short prints a skewed table.
    label = "REPO / TARGET"
    width = min(60, max([len(r["name"]) for r in found] + [len(label)]))
    org_w = min(22, max([len(r["org_name"]) for r in found] + [3])) if multi_org else 0

    header = f"   {'#':>4}  {label:<{width}}  "
    if multi_org:
        header += f"{'ORG':<{org_w}}  "
    header += f"{'ORIGIN':<10}  {'AGE':>5}"
    print(f"\n{bold(header)}", file=sys.stderr)
    print(dim("   " + "-" * (len(header) - 3)), file=sys.stderr)

    for n, r in enumerate(found, 1):
        recent = r["age_h"] is not None and r["age_h"] < RECENT_HOURS
        line = f"   {n:>4}  {r['name'][:width]:<{width}}  "
        if multi_org:
            line += f"{r['org_name'][:org_w]:<{org_w}}  "
        line += f"{str(r['origin'])[:10]:<10}  {fmt_age(r['age_h']):>5}"
        if recent:
            line += yellow("  <- new, import may still be running")
        print(line, file=sys.stderr)
    print(file=sys.stderr)


def parse_selection(ans, total):
    """'1,4,7-9' / 'all' / 'n' -> a sorted list of 1-based indices.

    Returns None for cancel. Out-of-range or malformed input is a cancel too,
    not a best-effort guess -- guessing at which targets someone meant to
    delete is not a thing to do.
    """
    ans = ans.strip().lower()
    if ans in ("", "n", "no", "none", "q", "cancel"):
        return None
    if ans in ("a", "all", "*"):
        return list(range(1, total + 1))

    picked = set()
    for part in ans.replace(" ", ",").split(","):
        if not part:
            continue
        if "-" in part[1:]:
            lo, _, hi = part.partition("-")
            if not (lo.isdigit() and hi.isdigit()):
                return None
            lo, hi = int(lo), int(hi)
            if lo > hi or lo < 1 or hi > total:
                return None
            picked.update(range(lo, hi + 1))
        elif part.isdigit() and 1 <= int(part) <= total:
            picked.add(int(part))
        else:
            return None
    return sorted(picked)


def choose_targets(found, args):
    """Which of the listed empty targets to act on. Returns a list of rows."""
    step("Select")

    recent = [r for r in found if r["age_h"] is not None and r["age_h"] < RECENT_HOURS]
    if recent and not args.include_recent:
        log_warn(f"{len(recent)} target(s) are under {RECENT_HOURS:g}h old and are "
                 "excluded from 'all' -- an import in flight looks exactly like a "
                 "failed one. Pass --include-recent to include them, or pick them "
                 "by number.")

    def bulk_set():
        if args.include_recent:
            return list(found)
        return [r for r in found
                if r["age_h"] is None or r["age_h"] >= RECENT_HOURS]

    if args.yes:
        chosen = bulk_set()
        item("Selected", f"{len(chosen)} target(s) (--yes)", cyan)
        return chosen

    if not sys.stdin.isatty():
        log("Not an interactive terminal and --yes was not passed -- reporting only.")
        return []

    while True:
        ans = ask("  Delete which? [e.g. 1,4,7-9 | all | n to cancel]: ")
        if ans.strip().lower() in ("a", "all", "*"):
            chosen = bulk_set()
            break
        picked = parse_selection(ans, len(found))
        if picked is None:
            log("Cancelled -- nothing selected.")
            return []
        chosen = [found[i - 1] for i in picked]
        break

    item("Selected", f"{len(chosen)} target(s)", cyan)
    return chosen


def confirm(chosen, args):
    """Final gate before anything is destroyed."""
    if args.yes:
        return True
    if not sys.stdin.isatty():
        return False
    print(file=sys.stderr)
    for r in chosen[:20]:
        item("", f"{r['name']}  {dim(r['org_name'])}")
    if len(chosen) > 20:
        item("", dim(f"... and {len(chosen) - 20} more"))
    log_warn(f"About to permanently delete {len(chosen)} target(s). "
             "This cannot be undone.")
    return ask("  Type DELETE to confirm: ") == "DELETE"


# ---------------------------------------------------------------------------

def write_csv(path, found, outcomes):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["org_name", "org_id", "target_name", "target_id", "origin",
                    "url", "created_at", "age", "outcome"])
        for r in found:
            w.writerow([
                r["org_name"], r["org_id"], r["name"], r["target_id"], r["origin"],
                r["url"], r["created"].isoformat() if r["created"] else "",
                fmt_age(r["age_h"]), outcomes.get(r["target_id"], "not selected"),
            ])
    log_ok(f"CSV written to {path}")


def parse_args():
    p = argparse.ArgumentParser(
        description="Find and delete Snyk targets that hold zero projects.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Dry run by default -- nothing is deleted without --apply.")
    p.add_argument("--group", default=os.environ.get("SNYK_GROUP_ID", ""),
                   help="group id to work in (default $SNYK_GROUP_ID; prompts if unset)")
    p.add_argument("--org", default="",
                   help="org name or id, instead of being prompted")
    p.add_argument("--all-orgs", action="store_true",
                   help="scan every org in the group")
    p.add_argument("--apply", action="store_true",
                   help="actually delete. Without it the run is a preview.")
    p.add_argument("--yes", action="store_true",
                   help="skip both prompts and take every listed target. For "
                        "unattended runs; combine with --apply.")
    p.add_argument("--filter", default="",
                   help="only targets whose name matches this glob, e.g. 'legacy-*'")
    p.add_argument("--exclude", default=os.environ.get("EXCLUDE_TARGETS", ""),
                   help="comma-separated globs to never touch")
    p.add_argument("--include-recent", action="store_true",
                   help=f"include targets under {RECENT_HOURS:g}h old in bulk "
                        "selections (they are usually imports still running)")
    p.add_argument("--max-deletes", type=int, default=DEFAULT_MAX_DELETES,
                   help=f"refuse to delete more than this in one run (default {DEFAULT_MAX_DELETES})")
    p.add_argument("--csv", default="",
                   help="write the full findings, and what happened to each, here")
    return p.parse_args()


def main():
    global _step_no
    _step_no = 0
    args = parse_args()
    excludes = [norm(x) for x in args.exclude.split(",") if x.strip()]

    scheme = detect_auth_scheme()
    log(f"Authenticated against {API_BASE} ({scheme} scheme)")

    group_id, group_name = choose_group(args.group)
    orgs = choose_orgs(group_id, args.org, args.all_orgs)

    # --- scan ---------------------------------------------------------------
    step("Scan for empty targets")
    found, failed = [], []
    for org_id, org_name in orgs:
        # A token can enumerate a group's orgs without being able to read inside
        # every one, and Snyk answers 404 (not 403) for an org it will not show
        # you. Skip that org rather than losing the whole run.
        try:
            found.extend(scan_org(org_id, org_name, args.filter, excludes))
        except (requests.HTTPError, RuntimeError) as e:
            code = getattr(getattr(e, "response", None), "status_code", "?")
            log_fail(f"{org_name}: SKIPPED (HTTP {code}) -- the token cannot read "
                     "this org")
            failed.append(org_name)

    if failed:
        log_warn(f"{len(failed)} org(s) could not be read ({', '.join(failed)}). "
                 "Empty targets in them are missing from this report.")

    if not found:
        log_ok("No empty targets found. Nothing to clean up.")
        if args.csv:
            write_csv(args.csv, [], {})
        return

    item("Empty targets", len(found), yellow)
    show_table(found, multi_org=len(orgs) > 1)

    # --- select -------------------------------------------------------------
    chosen = choose_targets(found, args)
    outcomes = {}

    if not chosen:
        if args.csv:
            write_csv(args.csv, found, outcomes)
        return

    if len(chosen) > args.max_deletes:
        log_fail(f"{len(chosen)} targets selected but --max-deletes is "
                 f"{args.max_deletes}. Raise it deliberately if that many really "
                 "should go.")
        if args.csv:
            write_csv(args.csv, found, outcomes)
        sys.exit(1)

    # --- delete -------------------------------------------------------------
    step("Delete" if args.apply else "Delete (dry run)")

    if not args.apply:
        log("Dry run -- nothing will be deleted. Re-run with --apply to act.")
        for r in chosen:
            item("would delete", f"{r['name']}  {dim(r['target_id'])}")
            outcomes[r["target_id"]] = "would delete (dry run)"
        item("Total", f"{len(chosen)} target(s) would be deleted", yellow)
        if args.csv:
            write_csv(args.csv, found, outcomes)
        return

    if not confirm(chosen, args):
        log("Not confirmed -- nothing deleted.")
        if args.csv:
            write_csv(args.csv, found, outcomes)
        return

    deleted = skipped = errors = 0
    for r in chosen:
        # Re-ask per target: the listing may be minutes old, and a target that
        # gained a project since then is no longer the thing that was approved.
        count = count_projects_for_target(r["org_id"], r["target_id"])
        if count != 0:
            reason = ("re-check failed" if count < 0
                      else f"no longer empty ({count} project(s))")
            log_warn(f"skipped {r['name']} -- {reason}")
            outcomes[r["target_id"]] = f"skipped: {reason}"
            skipped += 1
            continue

        ok, detail = delete_target(r["org_id"], r["target_id"])
        if ok:
            log_ok(f"{r['name']}  {dim(r['target_id'])}  {detail}")
            outcomes[r["target_id"]] = detail
            deleted += 1
        else:
            log_fail(f"{r['name']}: {detail}")
            outcomes[r["target_id"]] = f"failed: {detail}"
            errors += 1
        time.sleep(DELETE_DELAY)

    print(file=sys.stderr)
    item("Group", group_name)
    item("Deleted", deleted, green if deleted else None)
    item("Skipped", skipped, yellow if skipped else None)
    item("Failed", errors, red if errors else None)

    if args.csv:
        write_csv(args.csv, found, outcomes)

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(file=sys.stderr)
        log("Interrupted.")
        sys.exit(130)
