---
name: codeatlas
description: Evidence-first technical due diligence for software repositories. Use when asked to assess engineering and security risk for investment, acquisition, vendor, or platform reviews and produce reproducible JSON/PDF deliverables with staleness, dependency freshness, git-history secret exposure, and Security Maturity Index scoring.
---

# CodeAtlas

Run a technical due diligence pass that is metrics-heavy, reproducible, and privacy-safe. Prioritize codebase staleness, dependency freshness, secret exposure in git history, and SMI-driven risk adjustment.

## Use This Skill

Use this skill when the request includes one or more of these intents:

- Run technical due diligence or readiness scoring on a codebase.
- Produce a machine-readable risk matrix with evidence pointers.
- Scan the working tree and git history for leaked secrets.
- Classify discovered secrets as `prod_like`, `test_like`, or `unknown`.
- Generate an executive-ready PDF from structured diligence artifacts.

## Inputs

Accept an object aligned to `references/spec.json`.
Use these defaults unless the user overrides them:

- `timeframe_days=180`
- `stale_days=365`
- `risk_appetite=medium`
- `target_scale_multiplier=5`
- `report_format=both`
- `include_roadmap=true`
- `privacy_mode=true`
- `secret_scan.enabled=true`
- `secret_scan.scan_git_history=true`
- `secret_scan.scan_working_tree=true`
- `secret_scan.classify_test_vs_prod=true`
- `secret_scan.history_depth=all`

## Operating Mode

Select the highest-fidelity mode supported by available capabilities:

- `full`: shell and network available.
- `offline`: shell available, no network.
- `api_only`: no shell execution; use VCS APIs and lower confidence.

Always mark reduced confidence when mode is not `full`.

## Workflow

Execute this sequence:

1. Detect stack, repo facts, and operating mode.
2. Map architecture/components/dataflow.
3. Assess code health and test/CI posture.
4. Compute staleness and velocity metrics.
5. Inventory dependencies and freshness signals.
6. Assess DevOps/operability maturity.
7. Assess security/compliance and run secret scanning.
8. Assess data layer integrity controls.
9. Infer team/process/bus-factor signals.
10. Include Slack intelligence only when `slack.enabled=true` and capability exists.
11. Compute SMI, tier, and security multiplier.
12. Synthesize JSON artifacts and render PDF.

For every finding, emit:
1. Finding
2. Evidence
3. Risk
4. Recommended action
5. Confidence (`0-1`)

## Command

Run the orchestrator script from the skill directory:

```bash
python3 scripts/run_codeatlas.py \
  --repo /absolute/path/to/repo \
  --out /absolute/path/to/output \
  --timeframe-days 180 \
  --stale-days 365 \
  --risk-appetite medium \
  --report-format both
```

Generated outputs:
- `tdd_report_json`
- `risk_matrix_json`
- `metrics_summary_json`
- `security_maturity_index_json`
- `evidence_index_json`
- `slack_intel_json` (optional)
- `tdd_report_pdf` (when PDF engine available)

## Scoring Rules

Calculate:
- `base_tdd_score`
- `base_tdd_risk = 100 - base_tdd_score`
- `security_multiplier` from SMI tier mapping
- `adjusted_tdd_risk = base_tdd_risk * security_multiplier`
- `final_score = max(0, 100 - adjusted_tdd_risk)`

If `git_history_secrets_exposure.findings_count >= 1`, add at least one High/Critical security risk with rotation and control recommendations.

## Privacy Rules

- Never output secret values.
- Store only redacted indicators/fingerprints for secret findings.
- If `privacy_mode=true`, avoid contributor identities and present aggregates.
- For Slack analysis, never quote private content verbatim; summarize anonymized themes only.

## References

Read `references/spec.json` when full schema, metrics, and acceptance criteria are required.
