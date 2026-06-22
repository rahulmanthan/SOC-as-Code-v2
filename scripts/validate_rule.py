#!/usr/bin/env python3
"""
SOC-as-Code-v2 — Detection Rule Validation Orchestrator
======================================================
Validates a Sigma rule against real attack telemetry in three stages:
  1. Compile the Sigma rule to SPL
  2. Trigger the corresponding Atomic Red Team technique on the lab VM
  3. Query Splunk for detections and score: recall / leakage / noise

Usage:
    python validate_rule.py --rule rules/staging/execution/my_rule.yml

Environment variables required (never hardcode, never commit):
    SPLUNK_HOST      Splunk host (default: localhost)
    SPLUNK_PORT      Splunk REST API port (default: 8089)
    SPLUNK_USER      Splunk admin username
    SPLUNK_PASSWORD  Splunk admin password
    VM_HOST          Lab VM IP address
    VM_USER          Lab VM username
    VM_PASSWORD      Lab VM Administrator password
    ATOMICS_PATH     Path to atomics folder on the VM
                     (default: C:\\AtomicRedTeam\\atomic-red-team\\atomics)

Exit codes:
    0  Rule passed all corpus checks — production ready
    1  Rule failed one or more checks — needs review
    2  Infrastructure error — pipeline could not run
"""

import os
import sys
import json
import time
import shutil
import argparse
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import winrm
import requests
import urllib3
import yaml

# Suppress self-signed cert warnings for Splunk's default SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────
#  Configuration (from environment variables)
# ─────────────────────────────────────────────

def load_config():
    """Load all configuration from environment variables. Fail loudly if missing."""
    required = ["SPLUNK_USER", "SPLUNK_PASSWORD", "VM_HOST", "VM_USER", "VM_PASSWORD"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        print(f"[ERROR] Missing required environment variables: {', '.join(missing)}")
        print("        Set these in a .env file or export them before running.")
        sys.exit(2)

    return {
        "splunk_host":   os.environ.get("SPLUNK_HOST", "localhost"),
        "splunk_port":   int(os.environ.get("SPLUNK_PORT", "8089")),
        "splunk_user":   os.environ["SPLUNK_USER"],
        "splunk_pass":   os.environ["SPLUNK_PASSWORD"],
        "vm_host":       os.environ["VM_HOST"],
        "vm_user":       os.environ["VM_USER"],
        "vm_pass":       os.environ["VM_PASSWORD"],
        "atomics_path":  os.environ.get(
            "ATOMICS_PATH",
            r"C:\AtomicRedTeam\atomic-red-team\atomics"
        ),
        "atomic_module": os.environ.get(
            "ATOMIC_MODULE",
            r"C:\Users\Administrator\Documents\WindowsPowerShell\Modules"
            r"\Invoke-AtomicRedTeam\2.3.0\Invoke-AtomicRedTeam.psd1"
        ),
    }


# ─────────────────────────────────────────────
#  Step 1 — Parse the Sigma rule
# ─────────────────────────────────────────────

def parse_sigma_rule(rule_path):
    """
    Read the Sigma rule YAML and extract:
      - title
      - ATT&CK technique ID (from tags like attack.t1059.001)
      - level
    Returns a dict with these fields, or raises on failure.
    """
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    title = rule.get("title", Path(rule_path).stem)
    level = rule.get("level", "unknown")

    # Extract ATT&CK technique ID from tags
    technique_id = None
    for tag in rule.get("tags", []):
        tag = tag.lower()
        if tag.startswith("attack.t") and tag != "attack.execution":
            # e.g. "attack.t1059.001" → "T1059.001"
            raw = tag.replace("attack.", "").upper()
            technique_id = raw
            break

    if not technique_id:
        print(f"[WARNING] No ATT&CK technique ID found in rule tags.")
        print(f"          Add a tag like 'attack.t1059.001' for automated test mapping.")
        technique_id = None

    return {
        "title":        title,
        "level":        level,
        "technique_id": technique_id,
        "raw":          rule,
    }


# ─────────────────────────────────────────────
#  Step 2 — Compile Sigma rule to SPL
# ─────────────────────────────────────────────

def compile_sigma_to_spl(rule_path):
    """
    Use sigma-cli (pySigma) to compile the rule to SPL.
    Returns the compiled SPL string.
    """
    print(f"[1/4] Compiling Sigma rule to SPL...")

    result = subprocess.run(
        ["sigma", "convert", "-t", "splunk", "-p", "splunk_windows", str(rule_path)],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"[ERROR] Sigma compilation failed:")
        print(result.stderr)
        sys.exit(2)

    spl = result.stdout.strip()
    if not spl:
        print("[ERROR] Sigma compilation produced empty output.")
        sys.exit(2)

    print(f"        SPL: {spl[:120]}{'...' if len(spl) > 120 else ''}")
    return spl


# ─────────────────────────────────────────────
#  Step 3 — Execute Atomic Red Team on the VM
# ─────────────────────────────────────────────

def run_atomic_test(config, technique_id):
    """
    Connect to the lab VM via WinRM and execute the Atomic Red Team
    technique corresponding to this rule. Returns True on success.
    """
    if not technique_id:
        print("[2/4] Skipping atomic test execution — no technique ID in rule.")
        return False

    print(f"[2/4] Executing Invoke-AtomicTest {technique_id} on {config['vm_host']}...")

    # Build the PowerShell block to run on the VM
    # We import the module explicitly using the confirmed path,
    # then run the test and immediately clean up after it.
    ps_script = f"""
Import-Module "{config['atomic_module']}" -Force -ErrorAction SilentlyContinue
Invoke-AtomicTest {technique_id} `
    -PathToAtomicsFolder "{config['atomics_path']}" `
    -TimeoutSeconds 30 `
    -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Invoke-AtomicTest {technique_id} `
    -PathToAtomicsFolder "{config['atomics_path']}" `
    -Cleanup `
    -ErrorAction SilentlyContinue
Write-Output "ATOMIC_DONE"
"""

    try:
        session = winrm.Session(
            config["vm_host"],
            auth=(config["vm_user"], config["vm_pass"]),
            transport="ntlm",
            server_cert_validation="ignore",
            operation_timeout_sec=90,
            read_timeout_sec=100,
        )

        result = session.run_ps(ps_script)
        output = result.std_out.decode("utf-8", errors="replace")
        stderr = result.std_err.decode("utf-8", errors="replace")

        if "ATOMIC_DONE" in output:
            print(f"        Atomic test completed (status {result.status_code})")
            return True
        else:
            print(f"[WARNING] Atomic test may not have completed cleanly.")
            if stderr:
                print(f"          stderr: {stderr[:200]}")
            return True  # Still proceed — partial execution may still generate logs

    except Exception as e:
        print(f"[ERROR] WinRM execution failed: {e}")
        return False


# ─────────────────────────────────────────────
#  Step 4 — Query Splunk REST API
# ─────────────────────────────────────────────

def splunk_search(config, spl, earliest="-15m", latest="now", label=""):
    """
    Submit a Splunk search job and wait for results.
    Returns a list of result dicts (empty list if no hits).
    """
    base_url = f"https://{config['splunk_host']}:{config['splunk_port']}"
    auth = (config["splunk_user"], config["splunk_pass"])

    # Prepend 'search' keyword if missing (sigma convert omits it)
    if not spl.strip().startswith("search"):
        spl = "search " + spl

    # Submit the search job
    try:
        resp = requests.post(
            f"{base_url}/services/search/jobs",
            auth=auth,
            verify=False,
            data={
                "search": spl,
                "output_mode": "json",
                "earliest_time": earliest,
                "latest_time": latest,
            }
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Splunk job submission failed ({label}): {e}")
        return None

    job_id = resp.json()["sid"]

    # Poll until complete
    for attempt in range(20):
        time.sleep(3)
        status_resp = requests.get(
            f"{base_url}/services/search/jobs/{job_id}",
            auth=auth,
            verify=False,
            params={"output_mode": "json"}
        )
        status_data = status_resp.json()
        dispatch_state = status_data["entry"][0]["content"]["dispatchState"]
        if dispatch_state == "DONE":
            break
    else:
        print(f"[WARNING] Splunk job timed out ({label})")
        return []

    # Fetch results
    results_resp = requests.get(
        f"{base_url}/services/search/jobs/{job_id}/results",
        auth=auth,
        verify=False,
        params={"output_mode": "json", "count": 1000}
    )
    return results_resp.json().get("results", [])


# ─────────────────────────────────────────────
#  Step 5 — Score the rule
# ─────────────────────────────────────────────

def score_rule(config, spl, technique_id, indexing_wait=20):
    """
    Run the rule against three time windows and score:
      - target_hits:    events in the window right after atomic test execution
      - leakage_hits:   events from before the test (cross-domain / historical)
      - noise_rate:     hits per hour on a quiet baseline window (yesterday)
    """
    print(f"[3/4] Waiting {indexing_wait}s for Splunk to index atomic test telemetry...")
    time.sleep(indexing_wait)

    print(f"[4/4] Querying Splunk across three corpora...")

    # TARGET CORPUS — last 20 minutes (covers the atomic test we just ran)
    target_results = splunk_search(
        config, spl,
        earliest=f"-{indexing_wait + 60}s",
        latest="now",
        label="target"
    )
    target_hits = len(target_results) if target_results is not None else 0
    print(f"        Target corpus:      {target_hits} hit(s)")

    # CROSS-DOMAIN / LEAKAGE CORPUS — last 7 days excluding the last 20 min
    # This catches any historical false fires from unrelated activity
    leakage_results = splunk_search(
        config, spl,
        earliest="-7d",
        latest=f"-{indexing_wait + 60}s",
        label="cross-domain"
    )
    leakage_hits = len(leakage_results) if leakage_results is not None else 0
    print(f"        Cross-domain corpus: {leakage_hits} hit(s) (historical false positives)")

    # BENIGN BASELINE — 24 hours ago (a window with no atomic tests)
    baseline_results = splunk_search(
        config, spl,
        earliest="-48h",
        latest="-24h",
        label="benign-baseline"
    )
    baseline_hits = len(baseline_results) if baseline_results is not None else 0
    print(f"        Benign baseline:     {baseline_hits} hit(s) in 24h quiet window")

    return {
    "target_hits": target_hits,
    "historical_attack_hits": leakage_hits,
    "baseline_hits": baseline_hits,
    "target_sample": target_results[:3] if target_results else [],
}


# ─────────────────────────────────────────────
#  Step 6 — Gate logic and reporting
# ─────────────────────────────────────────────

THRESHOLDS = {
    # A rule PASSES if:
    "min_target_hits":    1,    # fired at least once on the atomic test
    "max_baseline_hits":  10,   # ≤10 fires in the 24h quiet baseline window
}

def evaluate(scores):
    """
    Evaluate the rule using:
      - Attack Recall
      - Benign Noise

    Historical attack hits are informational only and
    are NOT treated as failures.
    """

    reasons = []

    if scores["target_hits"] < THRESHOLDS["min_target_hits"]:
        reasons.append(
            f"FAIL — target corpus: {scores['target_hits']} hit(s), "
            f"need ≥{THRESHOLDS['min_target_hits']}. "
            f"Rule did not detect the Atomic Red Team execution."
        )

    if scores["baseline_hits"] > THRESHOLDS["max_baseline_hits"]:
        reasons.append(
            f"FAIL — benign baseline noise: {scores['baseline_hits']} hit(s) in 24h, "
            f"threshold ≤{THRESHOLDS['max_baseline_hits']}. "
            f"Rule generates excessive false positives."
        )

    return len(reasons) == 0, reasons

def classify_rule(scores):
    """
    STRONG:
        Detected attack
        No baseline noise
        Historical detections exist

    MODERATE:
        Detected attack
        Low baseline noise

    WEAK:
        Detected attack
        Noticeable baseline noise

    FAILED:
        Missed attack
    """

    if scores["target_hits"] == 0:
        return "FAILED"

    if (
        scores["baseline_hits"] == 0
        and scores["historical_attack_hits"] > 0
    ):
        return "STRONG"

    if scores["baseline_hits"] <= 5:
        return "MODERATE"

    return "WEAK"

def write_report(rule_meta, spl, scores, passed, reasons, report_dir="reports"):
    """Write a structured JSON + Markdown report to the reports/ directory."""
    Path(report_dir).mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rule_slug = Path(rule_meta.get("path", "unknown")).stem
    verdict = "PASS" if passed else "FAIL"
    classification = classify_rule(scores)

    report = {
        "timestamp":    timestamp,
        "rule":         rule_slug,
        "title":        rule_meta.get("title"),
        "technique_id": rule_meta.get("technique_id"),
        "level":        rule_meta.get("level"),
        "verdict":      verdict,
        "classification": classification,
        "scores":       scores,
        "thresholds":   THRESHOLDS,
        "reasons":      reasons,
        "compiled_spl": spl,
    }

    json_path = Path(report_dir) / f"{timestamp}_{rule_slug}_{verdict}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            report,
            f,
            indent=2,
            default=str,
            ensure_ascii=False
        )

    # Markdown summary (this gets posted as the PR comment by GitHub Actions)
    md_lines = [
        f"## SOC-as-Code-v2 Validation Report",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| Rule | `{rule_slug}` |",
        f"| Title | {rule_meta.get('title', 'N/A')} |",
        f"| Technique | {rule_meta.get('technique_id', 'N/A')} |",
        f"| Severity | {rule_meta.get('level', 'N/A')} |",
        f"| Timestamp | {timestamp} |",
        f"| **Verdict** | {'✅ PASS — promoted to production' if passed else '❌ FAIL — needs review'} |",
        f"| Classification | {classification} |",
        f"",
        f"### Three-Corpus Scores",
        f"",
        f"| Corpus | Hits | Threshold | Result |",
        f"|---|---|---|---|",
        f"| Target (atomic test window) | {scores['target_hits']} | ≥{THRESHOLDS['min_target_hits']} | {'✅' if scores['target_hits'] >= THRESHOLDS['min_target_hits'] else '❌'} |",
        f"| Historical attack detections (7d) | {scores['historical_attack_hits']} | Informational | PASS |",
        f"| Benign baseline (24h quiet window) | {scores['baseline_hits']} | ≤{THRESHOLDS['max_baseline_hits']} | {'✅' if scores['baseline_hits'] <= THRESHOLDS['max_baseline_hits'] else '❌'} |",
        f"",
    ]

    if not passed:
        md_lines += [
            f"### Failure Reasons",
            f"",
        ]
        for r in reasons:
            md_lines.append(f"- {r}")
        md_lines.append("")

    if scores.get("target_sample"):
        md_lines += [
            f"### Sample Detections (target corpus)",
            f"",
            f"```",
        ]
        for event in scores["target_sample"]:
            t = event.get("_time", "")
            cmd = event.get("CommandLine", event.get("_raw", ""))[:120]
            md_lines.append(f"{t}  {cmd}")
        md_lines += ["```", ""]

    md_lines += [
        f"### Compiled SPL",
        f"",
        f"```spl",
        spl,
        f"```",
        f"",
        f"*Full report: `{json_path.name}`*",
    ]

    md_path = Path(report_dir) / f"{timestamp}_{rule_slug}_{verdict}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    return str(json_path), str(md_path)


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SOC-as-Code-v2 — Sigma rule validation against real attack telemetry"
    )
    parser.add_argument(
        "--rule", required=True,
        help="Path to the Sigma rule YAML file to validate"
    )
    parser.add_argument(
        "--skip-atomic", action="store_true",
        help="Skip Atomic Red Team execution (use existing Splunk data only)"
    )
    parser.add_argument(
        "--report-dir", default="reports",
        help="Directory to write reports to (default: reports/)"
    )
    parser.add_argument(
        "--indexing-wait", type=int, default=20,
        help="Seconds to wait for Splunk indexing after atomic test (default: 20)"
    )
    parser.add_argument(
        "--output-md-path",
        help="Copy the markdown report to this path (for CI — lets the workflow "
             "know exactly where to find the report for the PR comment step)"
    )
    args = parser.parse_args()

    rule_path = Path(args.rule)
    if not rule_path.exists():
        print(f"[ERROR] Rule file not found: {rule_path}")
        sys.exit(2)

    print(f"\n{'='*60}")
    print(f"  SOC-as-Code-v2 Validation Pipeline")
    print(f"  Rule: {rule_path.name}")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}\n")

    # Load .env for local development; CI uses GitHub Secrets instead
    if not os.environ.get("GITHUB_ACTIONS"):
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass  # python-dotenv not installed — env vars must be set manually

    # Load config from environment
    config = load_config()

    # Parse rule
    rule_meta = parse_sigma_rule(rule_path)
    rule_meta["path"] = str(rule_path)
    technique_id = rule_meta["technique_id"]

    print(f"  Title:     {rule_meta['title']}")
    print(f"  Technique: {technique_id or 'not tagged'}")
    print(f"  Level:     {rule_meta['level']}\n")

    # Compile Sigma → SPL
    spl = compile_sigma_to_spl(rule_path)

    # Trigger atomic test (unless skipped)
    if not args.skip_atomic and technique_id:
        atomic_ran = run_atomic_test(config, technique_id)
    else:
        atomic_ran = False
        if args.skip_atomic:
            print("[2/4] Skipping atomic execution (--skip-atomic flag set)")
        else:
            print("[2/4] Skipping atomic execution (no technique ID tagged in rule)")

    # Score against three corpora
    indexing_wait = args.indexing_wait if atomic_ran else 0
    scores = score_rule(config, spl, technique_id, indexing_wait=indexing_wait)

    # Evaluate against thresholds
    passed, reasons = evaluate(scores)

    # Write report
    json_path, md_path = write_report(
        rule_meta, spl, scores, passed, reasons, args.report_dir
    )

    # Copy MD to a specific path if requested (CI integration)
    if args.output_md_path:
        Path(args.output_md_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(md_path, args.output_md_path)

    # Print summary
    print(f"\n{'='*60}")
    print(f"  VERDICT: {'✅ PASS' if passed else '❌ FAIL'}")
    if not passed:
        for r in reasons:
            print(f"  → {r}")
    print(f"\n  Reports written:")
    print(f"    {json_path}")
    print(f"    {md_path}")
    if args.output_md_path:
        print(f"    {args.output_md_path}  (CI copy)")
    print(f"{'='*60}\n")

    # Write verdict to GITHUB_OUTPUT so downstream steps can branch on it
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as ghf:
            ghf.write(f"verdict={'PASS' if passed else 'FAIL'}\n")
            ghf.write(f"report_json={json_path}\n")
            ghf.write(f"report_md={md_path}\n")

    # Exit code drives the GitHub Actions gate
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()