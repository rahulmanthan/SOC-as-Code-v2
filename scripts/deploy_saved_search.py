#!/usr/bin/env python3
"""
SOC-as-Code-v2 — Splunk Saved Search Deployment
================================================
Deploys a validated Sigma rule as a live Splunk saved search via the REST API.
This is the mechanism that turns rules/production/ into actual, functioning
SOC detection — not a metaphor, but real scheduled searches running in Splunk.

Usage:
    python deploy_saved_search.py --rule rules/production/execution/my_rule.yml
    python deploy_saved_search.py --list
    python deploy_saved_search.py --remove "SOCv2: My Rule Title"

Environment variables required:
    SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USER, SPLUNK_PASSWORD

Exit codes:
    0  Deployment succeeded / listing completed
    1  Deployment failed
    2  Infrastructure error (missing config, Splunk unreachable)
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path

import requests
import urllib3
import yaml

# Suppress self-signed cert warnings for Splunk's default SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Prefix for all SOC-as-Code saved searches — makes them easy to find and manage
SEARCH_PREFIX = "SOCv2"


def load_config():
    """Load Splunk connection config from environment variables."""
    required = ["SPLUNK_USER", "SPLUNK_PASSWORD"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        print(f"[ERROR] Missing required environment variables: {', '.join(missing)}")
        sys.exit(2)

    return {
        "host": os.environ.get("SPLUNK_HOST", "localhost"),
        "port": int(os.environ.get("SPLUNK_PORT", "8089")),
        "user": os.environ["SPLUNK_USER"],
        "pass": os.environ["SPLUNK_PASSWORD"],
    }


def compile_sigma_to_spl(rule_path):
    """Compile a Sigma rule to SPL using sigma-cli. Returns the SPL string."""
    # Check for custom SPL override
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    custom_spl = rule.get("custom", {}).get("spl_query")
    if custom_spl:
        return custom_spl

    result = subprocess.run(
        ["sigma", "convert", "-t", "splunk", "-p", "splunk_windows", str(rule_path)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[ERROR] Sigma compilation failed: {result.stderr}")
        return None

    spl = result.stdout.strip()
    if not spl:
        print("[ERROR] Sigma compilation produced empty output.")
        return None

    return spl


def parse_rule_meta(rule_path):
    """Extract metadata from the Sigma rule YAML."""
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    technique_id = None
    for tag in rule.get("tags", []):
        tag_lower = tag.lower()
        if tag_lower.startswith("attack.t"):
            technique_id = tag_lower.replace("attack.", "").upper()
            break

    return {
        "title": rule.get("title", Path(rule_path).stem),
        "description": rule.get("description", ""),
        "level": rule.get("level", "medium"),
        "technique_id": technique_id,
    }


def deploy_saved_search(config, rule_path, cron_schedule="*/5 * * * *"):
    """
    Create or update a Splunk saved search from a Sigma rule.
    The search is configured as a scheduled alert that fires when results > 0.
    """
    meta = parse_rule_meta(rule_path)
    spl = compile_sigma_to_spl(rule_path)

    if not spl:
        return False

    # Prepend 'search' keyword if missing
    if not spl.strip().startswith("search"):
        spl = "search " + spl

    search_name = f"{SEARCH_PREFIX}: {meta['title']}"
    base_url = f"https://{config['host']}:{config['port']}"
    auth = (config["user"], config["pass"])

    # Check if the saved search already exists
    check_resp = requests.get(
        f"{base_url}/servicesNS/nobody/search/saved/searches",
        auth=auth,
        verify=False,
        params={
            "output_mode": "json",
            "search": f"name=\"{search_name}\"",
            "count": 1,
        }
    )

    exists = False
    if check_resp.status_code == 200:
        entries = check_resp.json().get("entry", [])
        exists = any(e["name"] == search_name for e in entries)

    # Build the saved search payload
    payload = {
        "name":              search_name,
        "search":            spl,
        "is_scheduled":      "1",
        "cron_schedule":     cron_schedule,
        "dispatch.earliest_time": "-15m",
        "dispatch.latest_time":   "now",
        "alert_type":        "number of events",
        "alert_comparator":  "greater than",
        "alert_threshold":   "0",
        "alert.severity":    {"low": "2", "medium": "3", "high": "4", "critical": "5"}.get(
            meta["level"], "3"
        ),
        "description":       (
            f"[{SEARCH_PREFIX}] {meta['description'][:200]} "
            f"| Technique: {meta['technique_id'] or 'N/A'} "
            f"| Severity: {meta['level']}"
        ),
        "disabled":          "0",
    }

    if exists:
        # Update existing saved search
        print(f"[DEPLOY] Updating existing saved search: {search_name}")
        # Remove 'name' from payload for update (it's in the URL)
        update_payload = {k: v for k, v in payload.items() if k != "name"}
        resp = requests.post(
            f"{base_url}/servicesNS/nobody/search/saved/searches/{requests.utils.quote(search_name, safe='')}",
            auth=auth,
            verify=False,
            data=update_payload,
            params={"output_mode": "json"},
        )
    else:
        # Create new saved search
        print(f"[DEPLOY] Creating new saved search: {search_name}")
        resp = requests.post(
            f"{base_url}/servicesNS/nobody/search/saved/searches",
            auth=auth,
            verify=False,
            data=payload,
            params={"output_mode": "json"},
        )

    if resp.status_code in (200, 201):
        print(f"[OK] Saved search '{search_name}' deployed successfully.")
        print(f"     Schedule: {cron_schedule}")
        print(f"     SPL: {spl[:100]}{'...' if len(spl) > 100 else ''}")
        return True
    else:
        print(f"[ERROR] Splunk API returned {resp.status_code}:")
        try:
            error_msg = resp.json().get("messages", [{}])[0].get("text", resp.text[:300])
        except Exception:
            error_msg = resp.text[:300]
        print(f"        {error_msg}")
        return False


def list_saved_searches(config):
    """List all SOCv2-managed saved searches in Splunk."""
    base_url = f"https://{config['host']}:{config['port']}"
    auth = (config["user"], config["pass"])

    resp = requests.get(
        f"{base_url}/servicesNS/nobody/search/saved/searches",
        auth=auth,
        verify=False,
        params={
            "output_mode": "json",
            "count": 100,
            "search": f"name=\"{SEARCH_PREFIX}:*\"",
        }
    )

    if resp.status_code != 200:
        print(f"[ERROR] Failed to list saved searches: {resp.status_code}")
        return

    entries = resp.json().get("entry", [])
    soc_searches = [e for e in entries if e["name"].startswith(f"{SEARCH_PREFIX}:")]

    if not soc_searches:
        print(f"No {SEARCH_PREFIX} saved searches found in Splunk.")
        return

    print(f"\n{'='*60}")
    print(f"  {SEARCH_PREFIX} Saved Searches in Splunk ({len(soc_searches)})")
    print(f"{'='*60}\n")

    for entry in soc_searches:
        content = entry["content"]
        print(f"  📋 {entry['name']}")
        print(f"     Schedule:  {content.get('cron_schedule', 'N/A')}")
        print(f"     Enabled:   {'Yes' if content.get('disabled') == '0' else 'No'}")
        print(f"     Search:    {content.get('search', '')[:80]}...")
        print()


def remove_saved_search(config, search_name):
    """Remove a saved search from Splunk by name."""
    base_url = f"https://{config['host']}:{config['port']}"
    auth = (config["user"], config["pass"])

    resp = requests.delete(
        f"{base_url}/servicesNS/nobody/search/saved/searches/{requests.utils.quote(search_name, safe='')}",
        auth=auth,
        verify=False,
        params={"output_mode": "json"},
    )

    if resp.status_code == 200:
        print(f"[OK] Removed saved search: {search_name}")
        return True
    else:
        print(f"[ERROR] Failed to remove '{search_name}': {resp.status_code}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="SOC-as-Code-v2 — Deploy/manage Splunk saved searches"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--rule",
        help="Path to the production rule YAML to deploy as a saved search"
    )
    group.add_argument(
        "--list", action="store_true",
        help="List all SOCv2-managed saved searches in Splunk"
    )
    group.add_argument(
        "--remove",
        help="Remove a saved search by name (e.g. 'SOCv2: My Rule Title')"
    )
    parser.add_argument(
        "--cron", default="*/5 * * * *",
        help="Cron schedule for the saved search (default: every 5 minutes)"
    )
    args = parser.parse_args()

    # Load .env for local development
    if not os.environ.get("GITHUB_ACTIONS"):
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass

    config = load_config()

    if args.list:
        list_saved_searches(config)
    elif args.remove:
        success = remove_saved_search(config, args.remove)
        sys.exit(0 if success else 1)
    elif args.rule:
        rule_path = Path(args.rule)
        if not rule_path.exists():
            print(f"[ERROR] Rule file not found: {rule_path}")
            sys.exit(1)
        success = deploy_saved_search(config, rule_path, args.cron)

        # Write to GITHUB_OUTPUT if in CI
        github_output = os.environ.get("GITHUB_OUTPUT")
        if github_output and success:
            meta = parse_rule_meta(rule_path)
            with open(github_output, "a", encoding="utf-8") as f:
                f.write(f"search_name={SEARCH_PREFIX}: {meta['title']}\n")
                f.write(f"deployed=true\n")

        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
