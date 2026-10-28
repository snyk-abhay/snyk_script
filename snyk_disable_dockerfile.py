#!/usr/bin/env python3
"""
Bulk enable/disable Snyk "Detect Dockerfiles" across many Orgs, by driving the
web UI with your logged-in session (no API token needed).

WHAT THE TOGGLE IS

    Org Settings > Integrations > <GitHub | GitLab | ...> > Dockerfiles >
    "Enable Dockerfile detection"

    It is per SCM integration, so one org can have it on for GitHub and off for
    GitLab. The script visits every SCM integration page of each chosen org and
    sets the toggle wherever the "Detect Dockerfiles" card exists. Orgs with no
    SCM integration are reported as "no-scm" and left alone.

    The setting is NOT exposed by the integration-settings API (checked: the
    GitHub settings object has no Dockerfile field), so the script clicks the
    real toggle in a real browser and then reloads the page to confirm it stuck.

INTERACTIVE (no flags)

    python snyk_disable_dockerfile.py

    Flags only pre-answer a question (--enable, --insecure, --dry-run). If
    --apply/--dry-run is given but there is no orgs file, it asks which orgs.

    1. Reuses snyk_session.json, or opens a browser so you can log in (SSO/MFA).
    2. Asks: enable or disable?
    3. Lists your orgs; you choose all, some (numbers / names), or one group.
    4. Opens the browser and flips the toggle org by org, verifying each one.

WITH FLAGS (for scripting)

    set SNYK_TOKEN=...                                  # only for --fetch-orgs
    python snyk_disable_dockerfile.py --group <GROUP_ID> --fetch-orgs   # -> orgs_dockerfile.txt
    python snyk_disable_dockerfile.py --login                           # -> snyk_session.json
    python snyk_disable_dockerfile.py --orgs orgs_dockerfile.txt --dry-run
    python snyk_disable_dockerfile.py --orgs orgs_dockerfile.txt --apply            # turn OFF
    python snyk_disable_dockerfile.py --orgs orgs_dockerfile.txt --apply --enable   # turn ON

    orgs file: one "slug,org_id" per line (--fetch-orgs writes it).
    snyk_session.json is shared with snyk_disable_iac.py -- log in once.

SETUP
    pip install playwright && playwright install chromium

CORPORATE TLS PROXY (Zscaler / Netskope / Bluecoat etc.)
    Symptom: "unable to get local issuer certificate"
    Proper fix:  export NODE_EXTRA_CA_CERTS=/path/to/corp-root-ca.pem
    Quick fix:   add --insecure (disables cert checking for this script's browser)

REGIONS
    Non-US tenants: change APP_BASE / API_BASE, e.g. https://app.eu.snyk.io +
    https://api.eu.snyk.io.

NOTES
  * Needs Org Admin on every org; others fail to save and are reported.
  * progress_dockerfile.json checkpoints each org in --apply runs, so they are
    resumable. Delete it when switching between --enable and --disable.
  * Session cookies expire. If you get sent to the login page, log in again.
  * UNSUPPORTED: this depends on the page's markup (heading "Detect Dockerfiles",
    checkbox label "Enable Dockerfile detection"). If Snyk renames them, edit
    CARD_HEADING / TOGGLE_LABEL below.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

API_BASE = "https://api.snyk.io"
APP_BASE = "https://app.snyk.io"
REST_VERSION = "2024-10-15"
SESSION_FILE = "snyk_session.json"
PROGRESS_FILE = "progress_dockerfile.json"
DEFAULT_ORGS_FILE = "orgs_dockerfile.txt"

# SCM integrations as named by /api/v1/org/{id}/integrations; the same name is
# the page path under /org/{slug}/manage/integrations/. Registry integrations
# (ecr, acr, docker-hub...) have no Dockerfile card and are not visited.
SCM_TYPES = ["github", "github-enterprise", "gitlab", "bitbucket-cloud",
             "bitbucket-server", "bitbucket-connect-app", "azure-repos"]
INTEGRATION_PAGE = "{app}/org/{slug}/manage/integrations/{itype}"
CARD_HEADING = "Detect Dockerfiles"
TOGGLE_LABEL = "Enable Dockerfile detection"

TLS_HINT = (
    "\nTLS error -- your machine is behind a certificate-inspecting proxy.\n"
    "  Fix properly:  export NODE_EXTRA_CA_CERTS=/path/to/corp-root-ca.pem\n"
    "  Or bypass:     add --insecure to this command\n"
)

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class SessionExpired(Exception):
    pass


def safe_filename(name, flag):
    """Only a plain filename in the working directory -- no separators, no '..'.
    Returns the absolute path inside the current directory."""
    if not name or name != os.path.basename(name) or name in (".", ".."):
        sys.exit(f"{flag} must be a plain filename in the current directory, "
                 f"got {name!r}.")
    return os.path.join(os.getcwd(), os.path.basename(name))


def read_json(resp):
    try:
        return resp.json()
    except Exception:
        return None


def fetch_orgs(group_id, out_path=DEFAULT_ORGS_FILE):
    """'slug,org_id' per org in the group, via the public REST API."""
    token = os.environ.get("SNYK_TOKEN")
    if not token:
        sys.exit("Set SNYK_TOKEN to fetch orgs.")
    if not UUID_RE.match(group_id):
        sys.exit(f"--group must be a group UUID, got {group_id!r}.")
    out_path = safe_filename(out_path, "--orgs")

    rows, path, params = [], f"/rest/groups/{group_id}/orgs", {"limit": 100}
    while path:
        url = API_BASE + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(
                {**params, "version": REST_VERSION})
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"token {token}")
        with urllib.request.urlopen(req, timeout=60) as r:
            page = json.loads(r.read())
        for o in page.get("data", []):
            slug = o["attributes"].get("slug")
            if slug and o.get("id"):
                rows.append(f"{slug},{o['id']}")
        path, params = page.get("links", {}).get("next"), None

    with open(out_path, "w") as f:
        f.write("\n".join(rows) + "\n")
    print(f"{len(rows)} orgs -> {out_path}")


def read_orgs(path):
    path = safe_filename(path, "--orgs")
    if not os.path.exists(path):
        sys.exit(f"{os.path.basename(path)} not found. Run --group <ID> --fetch-orgs first.")
    orgs = []
    with open(path) as f:
        for n, ln in enumerate(f, 1):
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            slug, _, org_id = (p.strip() for p in ln.partition(","))
            if not slug or not org_id:
                sys.exit(f"{path}:{n}: expected 'slug,org_id', got {ln!r}. "
                         f"Run --fetch-orgs to generate the file.")
            orgs.append((slug, org_id))
    if not orgs:
        sys.exit(f"{path} is empty.")
    return orgs


def login(insecure):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        ctx = browser.new_context(ignore_https_errors=insecure)
        ctx.new_page().goto(f"{APP_BASE}/login")
        input("Log in (SSO/MFA included), land on the dashboard, then press Enter... ")
        ctx.storage_state(path=SESSION_FILE)
        browser.close()
    print(f"session saved -> {SESSION_FILE}")


def load_progress():
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE) as f:
            return json.load(f)
    return {}


def list_integrations(api, org_id):
    """Integration type names the org has (read-only). Raises SessionExpired."""
    resp = api.get(f"{APP_BASE}/api/v1/org/{org_id}/integrations",
                   headers={"Accept": "application/json",
                            "X-Requested-With": "XMLHttpRequest"},
                   timeout=30000)
    if resp.status in (401, 403):
        return None
    data = read_json(resp)
    return list(data) if resp.status == 200 and isinstance(data, dict) else None


def set_integration_toggle(page, slug, itype, target, apply_changes):
    """One integration page. Returns (status, detail):
    no-card | already | would-set | set | not-saved"""
    page.goto(INTEGRATION_PAGE.format(app=APP_BASE, slug=slug, itype=itype),
              wait_until="domcontentloaded", timeout=60000)
    if "/login" in page.url or "okta.com" in page.url:
        raise SessionExpired()

    def card():
        return page.locator(".settings-section-card",
                            has=page.get_by_role("heading", name=CARD_HEADING))

    try:
        card().first.wait_for(timeout=10000)
    except Exception:
        return "no-card", ""
    box = card().first.get_by_role("checkbox")
    current = box.is_checked()
    if current is target:
        return "already", "on" if current else "off"
    if not apply_changes:
        return "would-set", f"{'on' if current else 'off'} -> {'on' if target else 'off'}"

    # The input is styled away; the label is what a person clicks. No Save
    # button on this card -- it saves on change.
    card().first.get_by_text(TOGGLE_LABEL).click()
    page.wait_for_timeout(2000)
    page.reload(wait_until="domcontentloaded", timeout=60000)
    card().first.wait_for(timeout=10000)
    if card().first.get_by_role("checkbox").is_checked() is target:
        return "set", f"{'on' if current else 'off'} -> {'on' if target else 'off'}"
    return "not-saved", "toggle reverted after reload (not Org Admin?)"


def process_org(ctx, page, slug, org_id, target, apply_changes):
    """Returns (status, detail). status is 'ok' or a failure label."""
    types = list_integrations(ctx.request, org_id)
    if types is None:
        return "no-access", "could not list integrations (not a member / session)"
    scm = [t for t in types if t in SCM_TYPES]
    if not scm:
        return "no-scm", "no SCM integration -- left alone"

    parts, failed = [], False
    for itype in scm:
        status, detail = set_integration_toggle(page, slug, itype, target,
                                                apply_changes)
        if status == "no-card":
            continue
        parts.append(f"{itype}: {status}" + (f" ({detail})" if detail else ""))
        failed = failed or status == "not-saved"
    if not parts:
        return "no-card", "SCM page has no Dockerfile card -- left alone"
    return ("not-saved" if failed else "ok"), "; ".join(parts)


def run_orgs(orgs, apply_changes, enable, delay, insecure, headless, checkpoint):
    """orgs: [(slug, org_id)]. Drives the browser over them."""
    from playwright.sync_api import sync_playwright

    if not os.path.exists(SESSION_FILE):
        sys.exit(f"No {SESSION_FILE}. Run --login first.")

    target = bool(enable)
    prog = load_progress() if checkpoint else {}
    todo = [o for o in orgs if prog.get(o[0]) != "ok"]

    print(f"\n{len(orgs)} orgs, {len(todo)} to do | Dockerfile detection -> "
          f"{'ON' if target else 'OFF'} | "
          f"{'APPLY' if apply_changes else 'DRY RUN (read-only)'}"
          f"{' | INSECURE TLS' if insecure else ''}\n")

    results = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        ctx = browser.new_context(storage_state=SESSION_FILE,
                                  ignore_https_errors=insecure)
        page = ctx.new_page()
        try:
            for i, (slug, org_id) in enumerate(todo, 1):
                try:
                    status, detail = process_org(ctx, page, slug, org_id,
                                                 target, apply_changes)
                except SessionExpired:
                    browser.close()
                    sys.exit("\nSession expired -- you were sent to the login page. "
                             f"Delete {SESSION_FILE} (or run --login) and re-run.")
                except Exception as e:
                    msg = str(e)
                    if "issuer certificate" in msg or "SSL" in msg:
                        browser.close()
                        sys.exit(TLS_HINT)
                    status, detail = f"error:{type(e).__name__}", msg[:80]
                results[slug] = status
                if checkpoint:
                    prog[slug] = status
                    with open(PROGRESS_FILE, "w") as f:
                        json.dump(prog, f, indent=2)
                print(f"[{i}/{len(todo)}] {slug:40s} {status:10s} {detail}")
                if delay:
                    time.sleep(delay)
        finally:
            browser.close()

    counts = {}
    for v in results.values():
        counts[v] = counts.get(v, 0) + 1
    print("\nsummary:", counts)
    if "no-scm" in counts or "no-card" in counts:
        print("no-scm / no-card = nothing to toggle there (no SCM integration, or its "
              "page has no Dockerfile card). Not an error.")
    if "not-saved" in counts:
        print("not-saved = the click did not stick -- usually not Org Admin there.")
    if not apply_changes:
        print("\nDry run only -- nothing was changed. Add --apply to write.")


# ---------------------------------------------------------------- interactive

def ask(prompt, default=None):
    suffix = f" [{default}]" if default else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or default or ""


def ask_yes_no(prompt, default=False):
    answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not answer else answer.startswith("y")


def session_orgs(insecure):
    """Every org the logged-in user belongs to, via the session. None if the
    session is no longer valid."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(storage_state=SESSION_FILE,
                                  ignore_https_errors=insecure)
        try:
            resp = ctx.request.get(f"{APP_BASE}/api/v1/orgs",
                                   headers={"Accept": "application/json",
                                            "X-Requested-With": "XMLHttpRequest"},
                                   timeout=30000)
            status, data = resp.status, read_json(resp)
        except Exception as e:
            if "issuer certificate" in str(e) or "SSL" in str(e):
                sys.exit(TLS_HINT)
            raise
        finally:
            browser.close()
    if status != 200 or not isinstance(data, dict):
        return None
    return [o for o in data.get("orgs", []) if o.get("slug") and o.get("id")]


def choose_orgs(orgs):
    """Let the user pick: all / numbers / names / a whole group."""
    orgs = sorted(orgs, key=lambda o: (o.get("name") or o["slug"]).lower())

    groups = {}
    for o in orgs:
        g = o.get("group") or {}
        groups.setdefault(g.get("id"), [g.get("name") or "(no group)", []])[1].append(o)

    print(f"\nYou have {len(orgs)} orgs in {len(groups)} group(s).")
    print("  1. All orgs")
    print("  2. Choose a group")
    print("  3. Choose specific orgs")
    while True:
        menu = ask("Pick 1, 2 or 3")
        if menu == "1":
            return orgs
        if menu in ("2", "3"):
            break
        print("  please type 1, 2 or 3")

    if menu == "2":
        ids = list(groups)
        print("\nGroups:")
        for n, gid in enumerate(ids, 1):
            name, members = groups[gid]
            print(f"  {n}. {name}  ({len(members)} orgs)")
        while True:
            pick = ask("Group number (comma-separate for several)")
            nums = [t.strip() for t in pick.split(",") if t.strip()]
            if nums and all(t.isdigit() and 1 <= int(t) <= len(ids) for t in nums):
                return [o for t in dict.fromkeys(nums) for o in groups[ids[int(t) - 1]][1]]
            print(f"  please type numbers between 1 and {len(ids)}")

    print(f"\n{len(orgs)} orgs:")
    for n, o in enumerate(orgs, 1):
        gname = (o.get("group") or {}).get("name") or ""
        print(f"  {n:3d}. {o.get('name') or o['slug']}   [{gname}]")

    print("\nChoose orgs:  numbers like 1,4,7-9  |  part of an org or group "
          "name (e.g. atompro)  |  'all'")
    while True:
        raw = ask("Orgs")
        if not raw:
            continue
        if raw.lower() == "all":
            return orgs
        picked, ok = {}, True
        for tok in (t.strip() for t in raw.split(",") if t.strip()):
            m = re.fullmatch(r"(\d+)(?:-(\d+))?", tok)
            if m:
                lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
                if not (1 <= lo <= hi <= len(orgs)):
                    print(f"  {tok!r} is out of range 1-{len(orgs)}")
                    ok = False
                    break
                for i in range(lo, hi + 1):
                    picked[orgs[i - 1]["id"]] = orgs[i - 1]
            else:
                hits = [o for o in orgs
                        if tok.lower() in (o.get("name") or "").lower()
                        or tok.lower() in o["slug"].lower()
                        or tok.lower() in ((o.get("group") or {}).get("name") or "").lower()]
                if not hits:
                    print(f"  nothing matches {tok!r}")
                    ok = False
                    break
                for o in hits:
                    picked[o["id"]] = o
        if ok and picked:
            return list(picked.values())


def interactive(args):
    print("Snyk Dockerfile detection -- interactive mode\n")

    insecure = args.insecure or ask_yes_no(
        "Skip TLS certificate validation (corporate proxy)?")

    # 1. session
    if os.path.exists(SESSION_FILE):
        print(f"Using saved session ({SESSION_FILE}).")
    else:
        print(f"No {SESSION_FILE} yet -- opening a browser so you can log in.")
        login(insecure)

    print("Checking the session and loading your orgs...")
    orgs = session_orgs(insecure)
    if orgs is None:
        print("The saved session has expired -- logging in again.")
        login(insecure)
        orgs = session_orgs(insecure)
        if orgs is None:
            sys.exit("Still could not list orgs after logging in.")

    # 2. enable or disable (--enable on the command line answers this already)
    enable = args.enable
    if not enable:
        while True:
            answer = ask("\nTurn Dockerfile detection ON or OFF [on/off]").lower()
            if answer in ("on", "enable", "e"):
                enable = True
                break
            if answer in ("off", "disable", "d"):
                break
            print("  please type on or off")
    word = "ENABLE (ON)" if enable else "DISABLE (OFF)"

    # 3. which orgs
    chosen = choose_orgs(orgs)
    print(f"\nWill {word} Dockerfile detection on {len(chosen)} org(s):")
    for o in chosen[:15]:
        print(f"  - {o.get('name') or o['slug']}")
    if len(chosen) > 15:
        print(f"  ... and {len(chosen) - 15} more")
    apply_changes = not args.dry_run
    if apply_changes and not ask_yes_no(f"\nOpen the browser and {word} now?"):
        print("Nothing changed.")
        return

    # 4. do it in the browser
    run_orgs([(o["slug"], o["id"]) for o in chosen], apply_changes, enable,
             args.delay, insecure, headless=False, checkpoint=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--group")
    ap.add_argument("--fetch-orgs", action="store_true")
    ap.add_argument("--login", action="store_true")
    ap.add_argument("--orgs", default=DEFAULT_ORGS_FILE)
    ap.add_argument("--dry-run", action="store_true",
                    help="read each org's current state, change nothing")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--enable", action="store_true",
                    help="turn detection back ON instead of off")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS cert validation (corporate proxy workaround)")
    ap.add_argument("--headless", action="store_true",
                    help="flag mode only: hide the browser window")
    ap.add_argument("--delay", type=float, default=0.2)
    args = ap.parse_args()

    if args.fetch_orgs:
        if not args.group:
            sys.exit("--fetch-orgs needs --group")
        fetch_orgs(args.group, args.orgs)
    elif args.login:
        login(args.insecure)
    elif (args.dry_run or args.apply) and os.path.exists(
            safe_filename(args.orgs, "--orgs")):
        # scripted run: the orgs file is the answer to "which orgs?"
        run_orgs(read_orgs(args.orgs), args.apply, args.enable, args.delay,
                 args.insecure, args.headless, checkpoint=args.apply)
    else:
        # no flags, or flags without an orgs file: ask for what is missing
        interactive(args)


if __name__ == "__main__":
    main()
