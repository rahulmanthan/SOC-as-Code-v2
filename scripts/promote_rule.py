#!/usr/bin/env python3
"""
SOC-as-Code-v2 — Rule Promotion Script
=======================================
Called by the CI workflow when a staging rule PASSES all three corpus checks.
Promotes the rule from rules/staging/ to rules/production/ by:
  1. Determining the ATT&CK tactic subfolder from the rule's tags
  2. Copying the rule file to the correct production subfolder
  3. Outputting the destination path for downstream steps (Splunk deployment, git commit)

Usage:
    python promote_rule.py --rule rules/staging/execution/my_rule.yml

Exit codes:
    0  Rule promoted successfully
    1  Promotion failed (e.g., tactic not found, copy error)
"""

import os
import sys
import shutil
import argparse
from pathlib import Path

import yaml


# ─────────────────────────────────────────────
#  ATT&CK tactic tag → production subfolder
# ─────────────────────────────────────────────

TACTIC_MAP = {
    "attack.initial_access":       "initial_access",
    "attack.execution":            "execution",
    "attack.persistence":          "persistence",
    "attack.privilege_escalation": "privilege_escalation",
    "attack.defense_evasion":      "defense_evasion",
    "attack.credential_access":    "credential_access",
    "attack.discovery":            "discovery",
    "attack.lateral_movement":     "lateral_movement",
    "attack.collection":           "collection",
    "attack.command_and_control":  "command_and_control",
    "attack.exfiltration":         "exfiltration",
    "attack.impact":               "impact",
    "attack.reconnaissance":       "reconnaissance",
    "attack.resource_development": "resource_development",
}


def detect_tactic(rule_path):
    """
    Read the Sigma rule YAML and determine which ATT&CK tactic subfolder
    the rule should live in under rules/production/.
    Falls back to the staging subfolder name if no tactic tag is found.
    """
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    # Check tags for ATT&CK tactic
    for tag in rule.get("tags", []):
        tag_lower = tag.lower()
        if tag_lower in TACTIC_MAP:
            return TACTIC_MAP[tag_lower]

    # Fallback: use the parent directory name from the staging path
    # e.g. rules/staging/execution/rule.yml → "execution"
    parent = Path(rule_path).parent.name
    if parent and parent != "staging":
        print(f"[INFO] No tactic tag found; using staging subfolder name: {parent}")
        return parent

    print("[WARNING] Cannot determine tactic -- no ATT&CK tactic tag and no subfolder hint.")
    return None


def promote(rule_path, production_base="rules/production"):
    """
    Copy the rule from staging to production under the correct tactic subfolder.
    Returns the destination path on success.
    """
    rule_path = Path(rule_path)
    tactic = detect_tactic(rule_path)

    if not tactic:
        print("[ERROR] Could not determine production tactic folder. "
              "Add a tactic tag (e.g. 'attack.execution') to the rule.")
        return None

    dest_dir = Path(production_base) / tactic
    dest_dir.mkdir(parents=True, exist_ok=True)

    dest_path = dest_dir / rule_path.name
    shutil.copy2(str(rule_path), str(dest_path))

    print(f"[PROMOTE] {rule_path} -> {dest_path}")
    return str(dest_path)


def main():
    parser = argparse.ArgumentParser(
        description="SOC-as-Code-v2 — Promote a validated staging rule to production"
    )
    parser.add_argument(
        "--rule", required=True,
        help="Path to the staging rule YAML file to promote"
    )
    parser.add_argument(
        "--production-dir", default="rules/production",
        help="Base directory for production rules (default: rules/production)"
    )
    args = parser.parse_args()

    rule_path = Path(args.rule)
    if not rule_path.exists():
        print(f"[ERROR] Rule file not found: {rule_path}")
        sys.exit(1)

    dest = promote(rule_path, args.production_dir)

    if not dest:
        sys.exit(1)

    # Write to GITHUB_OUTPUT if running in CI
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"promoted_path={dest}\n")
            f.write(f"tactic={detect_tactic(rule_path)}\n")

    print(f"[OK] Rule promoted to {dest}")
    sys.exit(0)


if __name__ == "__main__":
    main()
