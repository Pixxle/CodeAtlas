# CodeAtlas — Technical Due Diligence Skill

CodeAtlas performs comprehensive technical due diligence on code repositories. It analyzes architecture, code quality, security, dependencies, testing, CI/CD, documentation, git health, performance, and infrastructure — producing a structured report backed by concrete evidence.

## Commands

- `/codeatlas:scan <path>` — Discover and fingerprint repositories at the target path
- `/codeatlas:analyze <path>` — Run full technical due diligence (discovery + analysis + report)
- `/codeatlas:report [output-dir]` — Generate a report from existing analysis files

## File Layout

```
references/                     # Detailed playbooks and templates
  analysis-dimensions.md        # 10-dimension investigative playbook
  cross-repo-synthesis.md       # Multi-repo synthesis agent instructions
  report-template.md            # Final report structure
scripts/
  repo-scanner.sh               # Bash discovery script
  install.sh                    # Global install script
```

## Output Convention

All analysis artifacts are written to `codeatlas-output/` in the current working directory:

```
codeatlas-output/
  discovery.md                  # Scan results
  analysis/
    <repo-name>/
      architecture.md
      code-quality/             # Split into focused sub-analyses
        code-style.md
        code-complexity.md
        code-debt.md
        code-error-handling.md
      dependencies.md
      security.md
      testing.md
      cicd.md
      documentation.md
      git-health.md
      performance.md
      infrastructure.md
  synthesis/
    cross-repo-synthesis.md
  report/
    tdd-report.md
```

## Global Install

To use `/codeatlas:*` commands from any project:

```bash
bash scripts/install.sh
```

This symlinks the commands to `~/.claude/commands/codeatlas/` and copies reference files to `~/.claude/codeatlas/`.

## Key Principles

- **Evidence over opinion.** Every claim must reference specific files, metrics, or command output.
- **Calibrate depth to risk.** A 2k LOC prototype needs less depth than a production system.
- **Separate facts from interpretation.** Present findings factually, then interpret.
- **Be fair.** Find warts, assess severity honestly, and suggest fixes — don't be harsh for its own sake.
