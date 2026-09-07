#!/usr/bin/env python3
"""
Bulk-disable Snyk IaC across every Organization in a Group (and optionally
delete the IaC Projects that were already created).

There is no Group-level "turn IaC off" switch in Snyk. The only supported
control is the per-Organization setting, so the way to do this at scale is to
enumerate the Orgs in the Group and loop.

Usage:
    export SNYK_TOKEN=...                 # Group Admin service account token
    python snyk_disable_iac.py --group <GROUP_ID> --probe          # inspect only
    python snyk_disable_iac.py --group <GROUP_ID> --dry-run
    python snyk_disable_iac.py --group <GROUP_ID> --apply
    python snyk_disable_iac.py --group <GROUP_ID> --apply --delete-projects

Notes:
  * --probe prints the current IaC settings payload for the first few Orgs.
    RUN THIS FIRST. The public schema for /orgs/{id}/settings/iac documents
    custom_rules; confirm which attribute your tenant exposes for the
    "Detect configuration files" toggle before mass-patching.
  * Disabling the setting does NOT remove existing IaC Projects. Use
    --delete-projects for that (irreversible: history is lost).
  * Self-hosted / EU / AU tenants: change API_BASE.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

API_BASE = "https://api.snyk.io"
REST_VERSION = "2024-10-15"
IAC_PROJECT_TYPES = [
    "terraformconfig", "terraformplan", "k8sconfig",
    "cloudformationconfig", "armconfig", "helmconfig",
]

TOKEN = os.environ.get("SNYK_TOKEN")
if not TOKEN:
    sys.exit("Set SNYK_TOKEN (Group Admin service account token).")


def call(method, path, params=None, body=None):
    url = f"{API_BASE}{path}"
    params = dict(params or {})
    if path.startswith("/rest"):
        params.setdefault("version", REST_VERSION)
    if params:
        from urllib.parse import urlencode
        url += ("&" if "?" in url else "?") + urlencode(params)

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"token {TOKEN}")
    if data:
        req.add_header("Content-Type", "application/vnd.api+json")

    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code == 429:                      # rate limited, back off
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"{method} {url} -> {e.code}: {e.read()[:400]}")
    raise RuntimeError(f"{method} {url} -> rate limited after retries")


def list_orgs(group_id):
    """Every Org in the Group, following REST pagination."""
    orgs, path, params = [], f"/rest/groups/{group_id}/orgs", {"limit": 100}
    while path:
        page = call("GET", path, params)
        orgs += [(o["id"], o["attributes"].get("name", "")) for o in page.get("data", [])]
        nxt = page.get("links", {}).get("next")
        if not nxt:
            break
        path, params = nxt, None                   # next link already carries query
    return orgs


def get_iac_settings(org_id):
    return call("GET", f"/rest/orgs/{org_id}/settings/iac")


def disable_iac(org_id, attributes):
    return call("PATCH", f"/rest/orgs/{org_id}/settings/iac",
                body={"data": {"type": "iac_settings",
                               "id": org_id,
                               "attributes": attributes}})


def iac_projects(org_id):
    projs, path = [], f"/rest/orgs/{org_id}/projects"
    params = {"limit": 100, "types": ",".join(IAC_PROJECT_TYPES)}
    while path:
        page = call("GET", path, params)
        projs += [(p["id"], p["attributes"].get("name", "")) for p in page.get("data", [])]
        nxt = page.get("links", {}).get("next")
        if not nxt:
            break
        path, params = nxt, None
    return projs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--group", required=True)
    ap.add_argument("--probe", action="store_true", help="print current settings, change nothing")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--delete-projects", action="store_true")
    ap.add_argument("--attributes", default='{"custom_rules": {"is_enabled": false}}',
                    help="JSON attributes body to PATCH; adjust after --probe")
    args = ap.parse_args()

    orgs = list_orgs(args.group)
    print(f"{len(orgs)} Organizations in group {args.group}\n")

    if args.probe:
        for org_id, name in orgs[:3]:
            print(f"--- {name} ({org_id})")
            print(json.dumps(get_iac_settings(org_id), indent=2))
        return

    attributes = json.loads(args.attributes)
    ok = failed = deleted = 0

    for org_id, name in orgs:
        if args.dry_run:
            print(f"[dry-run] would PATCH {name} ({org_id}) with {attributes}")
        elif args.apply:
            try:
                disable_iac(org_id, attributes)
                ok += 1
                print(f"[ok] {name} ({org_id})")
            except Exception as e:
                failed += 1
                print(f"[FAIL] {name} ({org_id}): {e}")
                continue

        if args.delete_projects:
            for pid, pname in iac_projects(org_id):
                if args.dry_run:
                    print(f"    [dry-run] would delete project {pname} ({pid})")
                else:
                    call("DELETE", f"/rest/orgs/{org_id}/projects/{pid}")
                    deleted += 1
                    print(f"    [deleted] {pname} ({pid})")

    print(f"\ndone: {ok} updated, {failed} failed, {deleted} projects deleted")


if __name__ == "__main__":
    main()
