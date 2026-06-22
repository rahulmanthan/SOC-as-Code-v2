# SOC-as-Code

A self-validating detection engineering pipeline. Every Sigma rule is proven
against real, freshly-executed attack telemetry — not synthetic logs — before
it is trusted in production.

This is the v2 evolution of an earlier project, **SOC-as-Code**, which
validated Sigma rules in a CI/CD pipeline against synthetic, self-generated
log data. This version closes that gap directly: rules here are tested
against telemetry produced by actually executing the corresponding [Atomic
Red Team] technique in an isolated lab, then validated against Splunk.

[Atomic Red Team]: https://github.com/redcanaryco/atomic-red-team

## How a rule earns production status

Every rule is evaluated against three corpora, not one:

| Corpus | What it proves |
|---|---|
| **Target** | Real logs from executing the exact ATT&CK technique (via Atomic Red Team) — does the rule actually fire on the attack it claims to catch? |
| **Cross-domain** | Real logs from *other*, unrelated techniques — does the rule stay silent outside its intended scope? |
| **Benign baseline** | Normal background activity — does the rule avoid drowning analysts in nuisance alerts? |

A rule only earns production status when it performs acceptably on all three.
This validation is automated via a GitHub Actions pipeline
(`.github/workflows/validate-rule.yml`) running on a self-hosted runner with
network access into the private lab. Pushing a rule to `rules/staging/` is
the only manual step — compilation, attack execution, Splunk querying,
three-corpus scoring, and report posting happen automatically.

## Repo layout

```
rules/
├── staging/         rules under test, not yet trusted
└── production/      validated rules, organized by ATT&CK tactic
    ├── execution/
    └── persistence/
scripts/
└── validate_rule.py orchestration script (compile → attack → score → report)
reports/             automated validation reports (JSON + Markdown)
.github/
├── workflows/
│   └── validate-rule.yml   CI/CD workflow — the "one click" pipeline
└── CODEOWNERS              enforces review for rules/production/ changes
docs/                validation log, design notes
```

## Promotion gate

Changes to `rules/production/` require review (see `.github/CODEOWNERS`),
enforced via branch protection. Rules that fail automated validation are
routed for review with an auto-filed issue documenting the failure, rather
than silently dropped or silently merged.

## Current rule set

| Rule | Technique | Tactic | Status |
|---|---|---|---|
| `T1059.001_encoded_powershell.yml` | T1059.001 | Execution | Production |
| `T1053.005_schtasks_shell_persistence.yml` | T1053.005 | Persistence | Production |

## Lab environment

- Windows Server 2025 (VirtualBox, host-only network)
- Sysmon (SwiftOnSecurity baseline config)
- Splunk Enterprise (Universal Forwarder on the lab VM)
- Invoke-AtomicRedTeam / Atomic Red Team atomics library
- Rules authored in Sigma, compiled to SPL via `pySigma`

## Build status

- [x] Lab telemetry pipeline (VM → Sysmon → Forwarder → Splunk) validated end to end
- [x] First Sigma rule manually validated against real attack telemetry
- [x] Second Sigma rule manually validated against real attack telemetry
- [x] Repository structure and promotion gate scaffolding
- [x] Self-hosted GitHub Actions runner
- [x] Automated orchestration (compile → trigger atomic test → score → report)
- [x] Full one-click validation loop (CI workflow wired)
- [ ] Production promotion gate (auto-promote passing rules + deploy Splunk saved searches)
- [ ] Auto-file GitHub Issues for failing rules
- [ ] Expansion to additional domains (credential access, defense evasion, C2)

