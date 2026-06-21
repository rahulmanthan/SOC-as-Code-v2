# SOC-as-Code v2

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
Right now this validation is done by hand (see `docs/validation-log.md` for
the record); a GitHub Actions pipeline with a self-hosted runner will
eventually automate the full loop — execute the atomic test, collect the
telemetry, compile and run the rule, score it, and route the result — so
that pushing a rule is the only manual step required.

## Repo layout

```
rules/
├── staging/      rules under test, not yet trusted
└── production/   validated rules, organized by ATT&CK tactic
    ├── execution/
    └── persistence/
reports/          automated validation reports land here (Phase 5+)
docs/             validation log, design notes
```

## Promotion gate

Changes to `rules/production/` require review (see `.github/CODEOWNERS`),
enforced via branch protection once this repo is connected to GitHub. Rules
that fail automated validation are routed back to `rules/staging/` with an
auto-filed issue documenting the failure, rather than silently dropped or
silently merged.

## Current rule set

| Rule | Technique | Tactic | Status |
|---|---|---|---|
| `T1059.001_encoded_powershell.yml` | T1059.001 | Execution | Production |
| `T1053.005_schtasks_shell_persistence.yml` | T1053.005 | Persistence | Production |

## Lab environment

- Windows Server 2025 (VMware, host-only network)
- Sysmon (SwiftOnSecurity baseline config)
- Splunk Enterprise (Universal Forwarder on the lab VM)
- Invoke-AtomicRedTeam / Atomic Red Team atomics library
- Rules authored in Sigma, compiled to SPL via `pySigma`

## Build status

- [x] Lab telemetry pipeline (VM → Sysmon → Forwarder → Splunk) validated end to end
- [x] First Sigma rule manually validated against real attack telemetry
- [x] Second Sigma rule manually validated against real attack telemetry
- [x] Repository structure and promotion gate scaffolding
- [ ] Self-hosted GitHub Actions runner
- [ ] Automated orchestration (compile → trigger atomic test → score → report)
- [ ] Full one-click validation loop
- [ ] Expansion to additional domains (authentication, network, cloud)
