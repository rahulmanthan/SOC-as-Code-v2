#!/usr/bin/env python3
"""
SOC-as-Code-v2 — File Review Issue for Failed Rules
====================================================
Called by the CI workflow when a staging rule FAILS validation.
Creates a GitHub Issue with the full validation report, assigns the
reviewer from CODEOWNERS, and labels the PR as 'needs-review'.

Usage:
    python file_review_issue.py \
        --rule rules/staging/execution/my_rule.yml \
        --report reports/ci_my_rule.md \
        --report-json reports/20260622T..._my_rule_FAIL.json

Environment variables required:
    GITHUB_TOKEN         Auto-provided by GitHub Actions
    GITHUB_REPOSITORY    Auto-provided (e.g. rahulmanthan/SOC-as-Code-v2)

Exit codes:
    0  Issue filed successfully
    1  Failed to file issue
"""

import os
import sys
import json
import argparse
from pathlib import Path

import requests
import yaml


def load_github_config():
    """Load GitHub API config from environment."""
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")

    if not token:
        print("[ERROR] GITHUB_TOKEN not set. This script must run inside GitHub Actions.")
        sys.exit(1)
    if not repo:
        print("[ERROR] GITHUB_REPOSITORY not set.")
        sys.exit(1)

    return {
        "token": token,
        "repo": repo,
        "api_base": "https://api.github.com",
    }


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
        "level": rule.get("level", "unknown"),
        "technique_id": technique_id or "unknown",
    }


def load_report(report_md_path, report_json_path=None):
    """Load the validation report markdown and optionally the JSON."""
    md_content = ""
    if report_md_path and Path(report_md_path).exists():
        with open(report_md_path, "r", encoding="utf-8") as f:
            md_content = f.read()

    json_data = {}
    if report_json_path and Path(report_json_path).exists():
        with open(report_json_path, "r", encoding="utf-8") as f:
            json_data = json.load(f)

    return md_content, json_data


def create_issue(config, title, body, labels=None, assignees=None):
    """Create a GitHub Issue via the REST API."""
    headers = {
        "Authorization": f"token {config['token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    payload = {
        "title": title,
        "body": body,
    }
    if labels:
        payload["labels"] = labels
    if assignees:
        payload["assignees"] = assignees

    resp = requests.post(
        f"{config['api_base']}/repos/{config['repo']}/issues",
        headers=headers,
        json=payload,
    )

    if resp.status_code == 201:
        issue = resp.json()
        print(f"[OK] Issue #{issue['number']} created: {issue['html_url']}")
        return issue
    else:
        print(f"[ERROR] Failed to create issue: {resp.status_code}")
        print(f"        {resp.text[:300]}")
        return None


def ensure_labels_exist(config, labels):
    """Create issue labels if they don't already exist."""
    headers = {
        "Authorization": f"token {config['token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    label_configs = {
        "needs-review": {
            "color": "d93f0b",
            "description": "Detection rule failed automated validation — requires human review"
        },
        "detection-engineering": {
            "color": "0075ca",
            "description": "Related to Sigma detection rule development and validation"
        },
    }

    for label in labels:
        if label not in label_configs:
            continue

        resp = requests.post(
            f"{config['api_base']}/repos/{config['repo']}/labels",
            headers=headers,
            json={
                "name": label,
                "color": label_configs[label]["color"],
                "description": label_configs[label]["description"],
            },
        )
        # 201 = created, 422 = already exists — both are fine
        if resp.status_code not in (201, 422):
            print(f"[WARNING] Could not create label '{label}': {resp.status_code}")


def add_label_to_pr(config, pr_number, labels):
    """Add labels to a pull request."""
    if not pr_number:
        return

    headers = {
        "Authorization": f"token {config['token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    resp = requests.post(
        f"{config['api_base']}/repos/{config['repo']}/issues/{pr_number}/labels",
        headers=headers,
        json={"labels": labels},
    )

    if resp.status_code == 200:
        print(f"[OK] Added labels {labels} to PR #{pr_number}")
    else:
        print(f"[WARNING] Could not add labels to PR #{pr_number}: {resp.status_code}")


def main():
    parser = argparse.ArgumentParser(
        description="SOC-as-Code-v2 — File a GitHub Issue for a failed detection rule"
    )
    parser.add_argument(
        "--rule", required=True,
        help="Path to the staging rule that failed validation"
    )
    parser.add_argument(
        "--report", required=True,
        help="Path to the markdown validation report"
    )
    parser.add_argument(
        "--report-json",
        help="Path to the JSON validation report (optional, for extra metadata)"
    )
    parser.add_argument(
        "--pr-number",
        help="PR number to label as needs-review (optional, from workflow context)"
    )
    parser.add_argument(
        "--assignee", default="rahulmanthan",
        help="GitHub username to assign the issue to (default: rahulmanthan)"
    )
    args = parser.parse_args()

    config = load_github_config()
    meta = parse_rule_meta(args.rule)
    md_content, json_data = load_report(args.report, args.report_json)

    # Build issue title
    issue_title = (
        f"[Detection Review] {meta['title']} — "
        f"FAIL on {meta['technique_id']}"
    )

    # Build issue body
    rule_filename = Path(args.rule).name
    body_parts = [
        f"## Detection Rule Failed Automated Validation",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Rule** | `{rule_filename}` |",
        f"| **Technique** | {meta['technique_id']} |",
        f"| **Severity** | {meta['level']} |",
        f"| **Staging path** | `{args.rule}` |",
        f"",
        f"### What happened",
        f"",
        f"This rule was automatically validated by the SOC-as-Code-v2 pipeline "
        f"against real attack telemetry (Atomic Red Team execution on the lab VM) "
        f"and **failed** one or more of the three-corpus checks (target recall, "
        f"cross-domain leakage, or benign baseline noise).",
        f"",
        f"### Action required",
        f"",
        f"Please review the validation report below and determine:",
        f"- Was the rule poorly written? (tuning needed)",
        f"- Did the Atomic Red Team test not generate the expected telemetry? (test issue)",
        f"- Is the Splunk data model / field extraction misaligned? (infra issue)",
        f"- Is the scoring threshold too strict for this rule? (threshold issue)",
        f"",
        f"---",
        f"",
        f"### Full Validation Report",
        f"",
    ]

    if md_content:
        body_parts.append(md_content)
    else:
        body_parts.append("*No markdown report available.*")

    # Add failure reasons from JSON if available
    if json_data.get("reasons"):
        body_parts += [
            f"",
            f"### Failure Reasons (from automated scoring)",
            f"",
        ]
        for reason in json_data["reasons"]:
            body_parts.append(f"- {reason}")

    body = "\n".join(body_parts)

    # Ensure labels exist
    labels = ["needs-review", "detection-engineering"]
    ensure_labels_exist(config, labels)

    # Create the issue
    issue = create_issue(
        config,
        title=issue_title,
        body=body,
        labels=labels,
        assignees=[args.assignee],
    )

    if not issue:
        sys.exit(1)

    # Label the PR if a PR number was provided
    if args.pr_number:
        add_label_to_pr(config, args.pr_number, ["needs-review"])

    # Write to GITHUB_OUTPUT if in CI
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output and issue:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"issue_number={issue['number']}\n")
            f.write(f"issue_url={issue['html_url']}\n")

    sys.exit(0)


if __name__ == "__main__":
    main()
