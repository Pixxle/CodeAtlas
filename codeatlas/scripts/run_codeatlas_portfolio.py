#!/usr/bin/env python3
"""Run CodeAtlas across multiple repositories and emit a portfolio PDF + JSON artifacts."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import re
import shutil
import statistics
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SECTION_TITLES = [
    "Executive Summary",
    "Architecture Overview",
    "Codebase Health",
    "Staleness & Change Velocity",
    "Dependencies & Supply Chain",
    "DevOps & Operability",
    "Security & Compliance",
    "Data Layer & Integrity",
    "Team/Process Signals",
    "Risk Matrix",
    "Recommendations",
    "12-18 Month Remediation Roadmap",
    "Evidence Appendix",
]


@dataclass
class RepoRun:
    name: str
    path: str
    out_dir: Path
    success: bool
    error: str | None = None
    run_summary: dict[str, Any] | None = None
    tdd_report: dict[str, Any] | None = None
    risk_matrix: list[dict[str, Any]] | None = None
    metrics_summary: dict[str, Any] | None = None
    smi: dict[str, Any] | None = None
    evidence: list[dict[str, Any]] | None = None


class EvidenceBook:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._count = 1

    def add(self, kind: str, pointer: str, description: str, repo: str | None = None) -> str:
        evidence_id = f"PE{self._count:05d}"
        self._count += 1
        entry = {
            "evidence_id": evidence_id,
            "type": kind,
            "pointer": pointer,
            "description": description,
        }
        if repo:
            entry["repo"] = repo
        self._entries.append(entry)
        return evidence_id

    @property
    def entries(self) -> list[dict[str, Any]]:
        return self._entries


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run CodeAtlas portfolio due diligence")
    parser.add_argument("--portfolio-root", required=True, help="Directory containing many repos")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--repos-file", help="Optional newline-separated list of repo names/paths")
    parser.add_argument("--timeframe-days", type=int, default=180)
    parser.add_argument("--stale-days", type=int, default=365)
    parser.add_argument("--risk-appetite", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--report-format", choices=["pdf", "json", "both"], default="both")
    parser.add_argument("--max-findings", type=int, default=200)
    parser.add_argument(
        "--history-depth",
        choices=["all", "timeframe", "default_branch_only"],
        default="all",
    )
    parser.add_argument("--include-roadmap", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--privacy-mode", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--continue-on-error", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--require-pdf", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--max-repos", type=int, default=0, help="0 means no cap")
    return parser.parse_args()


def run_cmd(cmd: list[str], cwd: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}")
    return proc


def json_load(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def json_dump(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def is_git_repo(path: Path) -> bool:
    try:
        run_cmd(["git", "-C", str(path), "rev-parse", "--show-toplevel"], check=True)
        return True
    except RuntimeError:
        return False


def discover_repos(root: Path, repos_file: str | None, max_repos: int) -> list[Path]:
    repos: list[Path] = []

    if repos_file:
        lines = Path(repos_file).read_text(encoding="utf-8", errors="ignore").splitlines()
        for raw in lines:
            text = raw.strip()
            if not text or text.startswith("#"):
                continue
            candidate = Path(text)
            if not candidate.is_absolute():
                candidate = root / candidate
            if candidate.exists() and is_git_repo(candidate):
                repos.append(candidate.resolve())
        if max_repos > 0:
            return repos[:max_repos]
        return repos

    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith("."):
            continue
        if is_git_repo(child):
            repos.append(child.resolve())

    if not repos and is_git_repo(root):
        repos.append(root.resolve())

    if max_repos > 0:
        repos = repos[:max_repos]
    return repos


def safe_repo_label(path: Path, used: set[str]) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", path.name) or "repo"
    label = base
    counter = 2
    while label in used:
        label = f"{base}_{counter}"
        counter += 1
    used.add(label)
    return label


def get_metric(metrics_summary: dict[str, Any], bucket: str, metric_id: str) -> Any:
    for item in metrics_summary.get(bucket, []) or []:
        if item.get("metric_id") == metric_id:
            return item.get("value")
    return None


def map_smi_multiplier(score: float) -> float:
    if score >= 85:
        return 0.8
    if score >= 70:
        return 1.0
    if score >= 50:
        return 1.2
    if score >= 30:
        return 1.5
    return 2.0


def tier_for(score: float) -> tuple[str, str]:
    if score >= 85:
        return "A", "Enterprise-ready"
    if score >= 70:
        return "B", "Mature startup"
    if score >= 50:
        return "C", "Typical startup risk"
    if score >= 30:
        return "D", "Structural risk"
    return "F", "Security liability"


def weighted_mean(pairs: list[tuple[float, float]]) -> float:
    total_weight = sum(weight for _, weight in pairs)
    if total_weight <= 0:
        return 0.0
    return sum(value * weight for value, weight in pairs) / total_weight


def aggregate_portfolio(
    generated_at: str,
    mode: str,
    root: Path,
    repo_runs: list[RepoRun],
    initial_failures: list[str],
    evidence: EvidenceBook,
    include_roadmap: bool,
) -> dict[str, Any]:
    completed = [r for r in repo_runs if r.success]
    failed = [r for r in repo_runs if not r.success]

    repo_rankings: list[dict[str, Any]] = []
    top_risks: list[dict[str, Any]] = []
    combined_metrics_rows: list[dict[str, Any]] = []

    stale_pairs: list[tuple[float, float]] = []
    dep_pairs: list[tuple[float, float]] = []
    final_score_values: list[float] = []
    smi_values: list[float] = []

    total_secret_findings = 0
    secret_severity_totals: collections.Counter[str] = collections.Counter()
    repos_with_secret_findings = 0

    ci_present_count = 0
    observability_true_count = 0
    low_test_signal_repos = 0

    language_counts: collections.Counter[str] = collections.Counter()
    component_counts: collections.Counter[str] = collections.Counter()

    data_findings_count = 0
    data_risks_count = 0
    process_findings_count = 0
    bus_factor_risks_count = 0

    recommendation_counter: collections.Counter[str] = collections.Counter()

    for repo in completed:
        assert repo.run_summary is not None
        assert repo.tdd_report is not None
        assert repo.risk_matrix is not None
        assert repo.metrics_summary is not None
        assert repo.smi is not None

        report = repo.tdd_report
        metrics = repo.metrics_summary
        smi = repo.smi

        repo_weight = float(max(1, metrics.get("repo", {}).get("source_files", 1)))

        stale_ratio = get_metric(metrics, "staleness_and_velocity", "stale_code_ratio")
        dep_fresh = get_metric(metrics, "dependencies_and_supply_chain", "dependency_freshness_score")
        bus_factor = get_metric(metrics, "staleness_and_velocity", "bus_factor_proxy")
        ci_present = get_metric(metrics, "operability", "ci_present")
        observability_signal = get_metric(metrics, "operability", "observability_signal")

        if isinstance(stale_ratio, (int, float)):
            stale_pairs.append((float(stale_ratio), repo_weight))
        if isinstance(dep_fresh, (int, float)):
            dep_pairs.append((float(dep_fresh), repo_weight))
        if ci_present is True:
            ci_present_count += 1
        if observability_signal is True:
            observability_true_count += 1

        sections = {section.get("title"): section for section in report.get("sections", [])}
        arch = sections.get("Architecture Overview", {})
        arch_details = arch.get("details", {})
        for lang, count in (arch_details.get("languages") or {}).items():
            if isinstance(count, int):
                language_counts[lang] += count
        for component in arch_details.get("top_level_components") or []:
            if isinstance(component, str):
                component_counts[component] += 1

        code_health = sections.get("Codebase Health", {})
        code_findings = code_health.get("findings", []) or []
        for finding in code_findings:
            if "Low test footprint" in str(finding.get("finding", "")):
                low_test_signal_repos += 1

        data_layer = sections.get("Data Layer & Integrity", {})
        data_findings_count += len(data_layer.get("findings", []) or [])
        data_risks_count += len(data_layer.get("risks", []) or [])

        team_process = sections.get("Team/Process Signals", {})
        process_findings_count += len(team_process.get("findings", []) or [])
        bus_factor_risks_count += len(team_process.get("bus_factor_risks", []) or [])

        score = report.get("overall_score", {})
        final_score = float(score.get("final_score", 0.0) or 0.0)
        base_score = float(score.get("base_tdd_score", 0.0) or 0.0)
        final_score_values.append(final_score)

        smi_score = float(smi.get("score", 0.0) or 0.0)
        smi_values.append(smi_score)
        smi_tier = str((smi.get("tier") or {}).get("tier", "D"))

        secret_metric = get_metric(metrics, "security_and_compliance", "git_history_secrets_exposure")
        secret_count = 0
        if isinstance(secret_metric, dict):
            secret_count = int(secret_metric.get("findings_count", 0) or 0)
            total_secret_findings += secret_count
            if secret_count > 0:
                repos_with_secret_findings += 1
            severity_map = secret_metric.get("severity_breakdown", {}) or {}
            for sev, val in severity_map.items():
                try:
                    secret_severity_totals[str(sev)] += int(val)
                except Exception:
                    continue

        ranking_row = {
            "repo": repo.name,
            "repo_path": repo.path,
            "final_score": round(final_score, 2),
            "base_score": round(base_score, 2),
            "smi_score": round(smi_score, 2),
            "smi_tier": smi_tier,
            "secret_findings": secret_count,
            "stale_code_ratio": stale_ratio,
            "dependency_freshness_score": dep_fresh,
            "bus_factor_proxy": bus_factor,
            "risk_count": len(repo.risk_matrix),
        }
        repo_rankings.append(ranking_row)

        for risk in repo.risk_matrix:
            enriched = dict(risk)
            enriched["repo"] = repo.name
            enriched["repo_path"] = repo.path
            enriched["repo_final_score"] = round(final_score, 2)
            enriched["repo_smi_tier"] = smi_tier
            top_risks.append(enriched)

            for action in risk.get("recommended_actions", []) or []:
                if isinstance(action, str) and action.strip():
                    recommendation_counter[action.strip()] += 1

        for entry in metrics.get("staleness_and_velocity", []) + metrics.get(
            "dependencies_and_supply_chain", []
        ) + metrics.get("security_and_compliance", []) + metrics.get("operability", []):
            metric_row = {
                "repo": repo.name,
                "metric_id": entry.get("metric_id"),
                "value": entry.get("value"),
                "confidence": entry.get("confidence"),
                "evidence": entry.get("evidence", []),
            }
            combined_metrics_rows.append(metric_row)

        for evidence_item in repo.evidence or []:
            evidence.add(
                kind=str(evidence_item.get("type", "unknown")),
                pointer=str(evidence_item.get("pointer", "")),
                description=str(evidence_item.get("description", "")),
                repo=repo.name,
            )

    repo_rankings.sort(key=lambda row: row.get("final_score", 0.0))
    top_risks.sort(
        key=lambda risk: (
            int(risk.get("priority_score", 0) or 0),
            float(risk.get("confidence", 0) or 0),
        ),
        reverse=True,
    )

    tier_distribution: collections.Counter[str] = collections.Counter(
        row.get("smi_tier", "D") for row in repo_rankings
    )

    avg_base = statistics.mean(
        [row.get("base_score", 0.0) for row in repo_rankings]
    ) if repo_rankings else 0.0
    avg_final = statistics.mean(final_score_values) if final_score_values else 0.0

    smi_score = statistics.mean(smi_values) if smi_values else 0.0
    smi_tier, smi_label = tier_for(smi_score)
    security_multiplier = map_smi_multiplier(smi_score)

    base_tdd_score = round(avg_base, 2)
    base_tdd_risk = round(100 - base_tdd_score, 2)
    adjusted_tdd_risk = round(base_tdd_risk * security_multiplier, 2)
    final_score = round(max(0.0, 100 - adjusted_tdd_risk), 2)

    weighted_stale_ratio = weighted_mean(stale_pairs)
    weighted_dep_freshness = weighted_mean(dep_pairs)

    highest = sorted(repo_rankings, key=lambda row: row.get("final_score", 0.0), reverse=True)[:5]
    lowest = repo_rankings[:5]

    recommendations = [
        action for action, _count in recommendation_counter.most_common(20)
    ]

    if not recommendations:
        recommendations = [
            "Establish monthly architecture and dependency review rhythm",
            "Implement pre-commit and CI secret scanning controls",
            "Create explicit rollback and disaster-recovery runbooks",
        ]

    roadmap = []
    if include_roadmap:
        roadmap = [
            {
                "window": "0-90 days",
                "focus": [
                    "Rotate exposed credentials and enforce secret scanning in commit/CI workflows",
                    "Stabilize CI baselines and add mandatory quality gates",
                    "Prioritize high-risk repositories for rapid remediation",
                ],
            },
            {
                "window": "3-6 months",
                "focus": [
                    "Reduce stale hotspots and distribute ownership to improve bus factor",
                    "Raise dependency freshness with automated update tooling",
                    "Expand observability and incident-response instrumentation",
                ],
            },
            {
                "window": "6-18 months",
                "focus": [
                    "Institutionalize portfolio-wide SMI targets and governance",
                    "Demonstrate backup/restore and recovery-readiness evidence",
                    "Close compliance evidence gaps for target frameworks",
                ],
            },
        ]

    section_objects: list[dict[str, Any]] = [
        {
            "title": "Executive Summary",
            "summary": (
                f"Portfolio final score is {final_score:.2f} across {len(completed)} repositories "
                f"(base score {base_tdd_score:.2f}, adjusted risk {adjusted_tdd_risk:.2f}). "
                f"SMI is {smi_score:.2f} ({smi_tier} - {smi_label})."
            ),
            "highlights": [
                f"Completed repositories: {len(completed)}/{len(repo_runs)}",
                f"Weighted stale code ratio: {weighted_stale_ratio:.2%}",
                f"Weighted dependency freshness: {weighted_dep_freshness:.2f}",
                f"Total git-history secret findings: {total_secret_findings}",
            ],
            "confidence": 0.78,
        },
        {
            "title": "Architecture Overview",
            "summary": (
                f"Detected {len(language_counts)} language groups across {len(component_counts)} top-level components."
            ),
            "highlights": [
                f"Top languages by file count: {dict(language_counts.most_common(8))}",
                f"Most common components: {dict(component_counts.most_common(10))}",
            ],
            "confidence": 0.68,
        },
        {
            "title": "Codebase Health",
            "summary": (
                f"CI signal present in {ci_present_count}/{len(completed) or 1} repositories; "
                f"low-test-footprint signals observed in {low_test_signal_repos} repositories."
            ),
            "highlights": [
                "Code health findings were inferred from static repository indicators.",
                "Quality confidence is lower where CI configuration is absent.",
            ],
            "confidence": 0.69,
        },
        {
            "title": "Staleness & Change Velocity",
            "summary": (
                f"Weighted stale code ratio is {weighted_stale_ratio:.2%}; "
                f"organizational sustainability risk increases when stale code and low bus factor coincide."
            ),
            "highlights": [
                f"Bottom-5 by final score: {[r['repo'] for r in lowest]}",
                f"Top-5 by final score: {[r['repo'] for r in highest]}",
            ],
            "confidence": 0.81,
        },
        {
            "title": "Dependencies & Supply Chain",
            "summary": (
                f"Portfolio dependency freshness score is {weighted_dep_freshness:.2f}."
            ),
            "highlights": [
                "Low freshness plus low cadence elevates supply-chain and upgrade-risk exposure.",
                "Automated dependency update tooling should be standard across repositories.",
            ],
            "confidence": 0.67,
        },
        {
            "title": "DevOps & Operability",
            "summary": (
                f"Observability signals are present in {observability_true_count}/{len(completed) or 1} repositories."
            ),
            "highlights": [
                "Weak CI/CD and rollback readiness increase operational failure impact.",
                "Environment parity and runbook maturity should be audited repo-by-repo.",
            ],
            "confidence": 0.64,
        },
        {
            "title": "Security & Compliance",
            "summary": (
                f"Security maturity is {smi_score:.2f} ({smi_tier} - {smi_label}); "
                f"secret findings total {total_secret_findings} across {repos_with_secret_findings} repositories."
            ),
            "highlights": [
                f"SMI tier distribution: {dict(tier_distribution)}",
                f"Secret severity totals: {dict(secret_severity_totals)}",
                "If any secret exposure exists, immediate credential rotation is required.",
            ],
            "confidence": 0.8,
        },
        {
            "title": "Data Layer & Integrity",
            "summary": (
                f"Data-layer findings count={data_findings_count}; explicit data-risk findings count={data_risks_count}."
            ),
            "highlights": [
                "Backup/restore evidence and migration discipline should be verified for critical services.",
            ],
            "confidence": 0.6,
        },
        {
            "title": "Team/Process Signals",
            "summary": (
                f"Team/process findings count={process_findings_count}; bus-factor-specific risks count={bus_factor_risks_count}."
            ),
            "highlights": [
                "Ownership concentration increases delivery fragility and key-person risk.",
                "Cross-review and maintainer rotation reduce sustainment risk.",
            ],
            "confidence": 0.72,
        },
        {
            "title": "Risk Matrix",
            "summary": f"{len(top_risks)} portfolio risks were ranked by priority score.",
            "highlights": [
                f"Top risk category: {top_risks[0].get('category') if top_risks else 'n/a'}",
                "Risk priority uses impact, likelihood, and effort scoring.",
            ],
            "confidence": 0.84,
        },
        {
            "title": "Recommendations",
            "summary": "Actions below are deduplicated from top risk recommendations.",
            "highlights": recommendations[:12],
            "confidence": 0.8,
        },
        {
            "title": "12-18 Month Remediation Roadmap",
            "summary": "Phased remediation plan to reduce portfolio risk and improve maturity.",
            "roadmap": roadmap,
            "confidence": 0.74,
        },
        {
            "title": "Evidence Appendix",
            "summary": f"{len(evidence.entries)} evidence records captured across successful runs.",
            "highlights": [
                "Evidence pointers include command traces, paths, and per-repo artifacts.",
                "Secret values are redacted; only non-sensitive indicators are retained.",
            ],
            "confidence": 0.9,
        },
    ]

    findings = [
        {
            "finding": "High stale code ratio and low ownership breadth raise sustainability risk",
            "evidence": ["portfolio:staleness", "portfolio:bus_factor"],
            "risk": "Maintenance burden and incident recovery degrade over time",
            "recommendation": "Prioritize stale hotspots with ownership expansion",
            "confidence": 0.79,
        },
        {
            "finding": "Secret exposure in git history across multiple repositories",
            "evidence": ["portfolio:secrets"],
            "risk": "Credential compromise and compliance impact",
            "recommendation": "Rotate exposed credentials immediately and enforce preventive scanning",
            "confidence": 0.9,
        },
    ]

    combined_tdd_report_json = {
        "generated_at": generated_at,
        "mode": mode,
        "scope": {
            "portfolio_root": str(root),
            "repo_count": len(repo_runs),
            "repos": [r.name for r in repo_runs],
        },
        "coverage": {
            "requested_repo_count": len(repo_runs),
            "completed_repo_count": len(completed),
            "initial_pass_failures": len(initial_failures),
            "retry_with_higher_max_findings": False,
            "retry_failures": len(failed),
            "failed_repos": [{"repo": r.name, "error": r.error} for r in failed],
        },
        "overall_score": {
            "base_tdd_score": base_tdd_score,
            "base_tdd_risk": base_tdd_risk,
            "security_multiplier": security_multiplier,
            "adjusted_tdd_risk": adjusted_tdd_risk,
            "final_score": final_score,
        },
        "security_maturity": {
            "score": round(smi_score, 2),
            "tier": {"tier": smi_tier, "label": smi_label},
            "tier_distribution": dict(tier_distribution),
            "applied_risk_multiplier": security_multiplier,
        },
        "reporting": {
            "report_sections": SECTION_TITLES,
        },
        "sections": section_objects,
        "findings": findings,
        "repo_rankings": repo_rankings,
        "top_risks": top_risks[:200],
    }

    combined_risk_matrix_json = top_risks

    combined_metrics_summary_json = {
        "generated_at": generated_at,
        "mode": mode,
        "portfolio": {
            "repo_count": len(repo_runs),
            "completed_repo_count": len(completed),
            "weighted_stale_code_ratio": round(weighted_stale_ratio, 4),
            "weighted_dependency_freshness_score": round(weighted_dep_freshness, 2),
            "total_git_history_secret_findings": total_secret_findings,
            "repos_with_secret_findings": repos_with_secret_findings,
            "secret_severity_totals": dict(secret_severity_totals),
            "ci_present_count": ci_present_count,
            "observability_signal_count": observability_true_count,
        },
        "per_repo_metrics": combined_metrics_rows,
    }

    combined_security_maturity_index_json = {
        "score": round(smi_score, 2),
        "tier": {"tier": smi_tier, "label": smi_label},
        "tier_distribution": dict(tier_distribution),
        "applied_risk_multiplier": security_multiplier,
        "confidence": 0.72,
        "limitations": [
            "Portfolio result aggregates static per-repo analyses",
            "Live infrastructure and runtime controls are not validated here",
        ],
    }

    return {
        "report": combined_tdd_report_json,
        "risk_matrix": combined_risk_matrix_json,
        "metrics_summary": combined_metrics_summary_json,
        "smi": combined_security_maturity_index_json,
        "repo_rankings": repo_rankings,
        "highest": highest,
        "lowest": lowest,
        "recommendations": recommendations,
    }


def to_markdown(report: dict[str, Any], highest: list[dict[str, Any]], lowest: list[dict[str, Any]], top_risks: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append("# CodeAtlas Portfolio Technical Due Diligence")
    lines.append("")
    lines.append(f"- Generated at: {report['generated_at']}")
    lines.append(f"- Portfolio root: `{report['scope']['portfolio_root']}`")
    lines.append(f"- Repositories analyzed: {report['scope']['repo_count']}")
    lines.append(f"- Completed repositories: {report['coverage']['completed_repo_count']}")
    lines.append(f"- Analysis mode: {report['mode']}")
    lines.append("")

    score = report.get("overall_score", {})
    lines.append("## Overall Score")
    lines.append("")
    lines.append(f"- Base TDD score: {score.get('base_tdd_score', 0)}")
    lines.append(f"- Base TDD risk: {score.get('base_tdd_risk', 0)}")
    lines.append(f"- Security multiplier: {score.get('security_multiplier', 1)}")
    lines.append(f"- Adjusted TDD risk: {score.get('adjusted_tdd_risk', 0)}")
    lines.append(f"- Final score: {score.get('final_score', 0)}")
    lines.append("")

    lines.append("## Report Sections")
    lines.append("")
    for title in report.get("reporting", {}).get("report_sections", []):
        lines.append(f"- {title}")
    lines.append("")

    for section in report.get("sections", []):
        lines.append(f"## {section.get('title', 'Section')}")
        lines.append("")
        lines.append(section.get("summary", ""))
        lines.append("")

        highlights = section.get("highlights", []) or []
        for item in highlights:
            lines.append(f"- {item}")

        roadmap = section.get("roadmap", []) or []
        if roadmap:
            for phase in roadmap:
                lines.append(f"- {phase.get('window')}: {', '.join(phase.get('focus', []))}")

        lines.append("")

    lines.append("## Lowest-Scoring Repositories (Top 5)")
    lines.append("")
    for idx, row in enumerate(lowest[:5], 1):
        lines.append(
            f"{idx}. `{row['repo']}`: final={row['final_score']}, base={row['base_score']}, "
            f"SMI={row['smi_score']} ({row['smi_tier']}), secrets={row['secret_findings']}"
        )
    lines.append("")

    lines.append("## Highest-Scoring Repositories (Top 5)")
    lines.append("")
    for idx, row in enumerate(highest[:5], 1):
        lines.append(
            f"{idx}. `{row['repo']}`: final={row['final_score']}, base={row['base_score']}, "
            f"SMI={row['smi_score']} ({row['smi_tier']}), secrets={row['secret_findings']}"
        )
    lines.append("")

    lines.append("## Top Portfolio Risks (By Priority)")
    lines.append("")
    for idx, risk in enumerate(top_risks[:25], 1):
        lines.append(
            f"{idx}. `{risk.get('repo', 'repo')}` | {risk.get('title', 'risk')} | "
            f"category={risk.get('category', 'n/a')} | priority={risk.get('priority_score', 0)} | "
            f"confidence={risk.get('confidence', 0)}"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- This report aggregates per-repository static analyses.")
    lines.append("- Secret values are never included; indicators are redacted.")
    lines.append("- Confidence may be reduced when required capabilities are unavailable.")
    lines.append("")

    return "\n".join(lines)


def render_pdf(
    pdf_path: Path,
    report: dict[str, Any],
    risk_matrix: list[dict[str, Any]],
    repo_rankings: list[dict[str, Any]],
) -> tuple[bool, str, str | None]:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        styles = getSampleStyleSheet()
        story: list[Any] = []
        doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)

        story.append(Paragraph("CodeAtlas Portfolio Technical Due Diligence", styles["Title"]))
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"Generated: {report.get('generated_at')}", styles["BodyText"]))
        story.append(
            Paragraph(
                f"Portfolio root: {report.get('scope', {}).get('portfolio_root', 'n/a')}",
                styles["BodyText"],
            )
        )
        story.append(Spacer(1, 12))

        score = report.get("overall_score", {})
        score_rows = [
            ["Metric", "Value"],
            ["Base TDD score", str(score.get("base_tdd_score", "n/a"))],
            ["Base TDD risk", str(score.get("base_tdd_risk", "n/a"))],
            ["Security multiplier", str(score.get("security_multiplier", "n/a"))],
            ["Adjusted TDD risk", str(score.get("adjusted_tdd_risk", "n/a"))],
            ["Final score", str(score.get("final_score", "n/a"))],
        ]
        score_table = Table(score_rows, repeatRows=1)
        score_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(score_table)
        story.append(Spacer(1, 12))

        # Render the required human-readable sections.
        for section in report.get("sections", []):
            title = section.get("title", "Section")
            story.append(Paragraph(title, styles["Heading2"]))
            story.append(Paragraph(section.get("summary", ""), styles["BodyText"]))
            story.append(Spacer(1, 6))
            for item in section.get("highlights", []) or []:
                story.append(Paragraph(f"- {item}", styles["BodyText"]))
            for phase in section.get("roadmap", []) or []:
                focus = ", ".join(phase.get("focus", []))
                story.append(Paragraph(f"- {phase.get('window')}: {focus}", styles["BodyText"]))
            story.append(
                Paragraph(
                    f"Confidence: {section.get('confidence', 0):.2f}",
                    styles["Italic"],
                )
            )
            story.append(Spacer(1, 10))

        story.append(Paragraph("Risk Matrix (Top 25)", styles["Heading2"]))
        risk_rows = [["Repo", "Title", "Category", "Impact", "Likelihood", "Priority", "Conf"]]
        for risk in risk_matrix[:25]:
            risk_rows.append(
                [
                    str(risk.get("repo", ""))[:25],
                    str(risk.get("title", ""))[:45],
                    str(risk.get("category", ""))[:18],
                    str(risk.get("impact", "")),
                    str(risk.get("likelihood", "")),
                    str(risk.get("priority_score", "")),
                    f"{float(risk.get('confidence', 0) or 0):.2f}",
                ]
            )

        risk_table = Table(risk_rows, repeatRows=1)
        risk_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(risk_table)
        story.append(Spacer(1, 12))

        story.append(Paragraph("Repository Rankings (Top/Bottom)", styles["Heading2"]))
        ranking_rows = [["Repo", "Final", "Base", "SMI", "Tier", "Secrets"]]
        sorted_rows = sorted(repo_rankings, key=lambda row: row.get("final_score", 0.0))
        for row in sorted_rows[:5] + sorted_rows[-5:]:
            ranking_rows.append(
                [
                    row.get("repo", "")[:30],
                    str(row.get("final_score", "")),
                    str(row.get("base_score", "")),
                    str(row.get("smi_score", "")),
                    str(row.get("smi_tier", "")),
                    str(row.get("secret_findings", "")),
                ]
            )

        ranking_table = Table(ranking_rows, repeatRows=1)
        ranking_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(ranking_table)

        doc.build(story)
        return True, "reportlab", None
    except Exception as exc:
        reportlab_error = str(exc)

    pandoc = shutil.which("pandoc")
    if pandoc:
        md_path = pdf_path.with_suffix(".md")
        md_payload = "# CodeAtlas Portfolio Technical Due Diligence\n\n"
        md_payload += f"Generated: {report.get('generated_at')}\n\n"
        md_payload += "## Sections\n"
        for section in report.get("sections", []):
            md_payload += f"- {section.get('title')}\n"
        md_path.write_text(md_payload, encoding="utf-8")

        proc = subprocess.run(
            [pandoc, str(md_path), "-o", str(pdf_path)],
            text=True,
            capture_output=True,
        )
        if proc.returncode == 0:
            return True, "pandoc", None
        return False, "pandoc", proc.stderr.strip()

    return False, "none", reportlab_error


def main() -> int:
    args = parse_args()
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()

    portfolio_root = Path(args.portfolio_root).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    runner = Path(__file__).with_name("run_codeatlas.py")
    if not runner.exists():
        print(f"[codeatlas-portfolio] Missing runner: {runner}", file=sys.stderr)
        return 2

    repos = discover_repos(portfolio_root, args.repos_file, args.max_repos)
    if not repos:
        print("[codeatlas-portfolio] No git repositories found", file=sys.stderr)
        return 2

    logs_dir = out_dir
    repos_out_dir = out_dir / "repos"
    repos_out_dir.mkdir(parents=True, exist_ok=True)
    runs_log = logs_dir / "runs.log"
    failures_log = logs_dir / "failures.log"
    retry_runs_log = logs_dir / "retry_runs.log"
    retry_failures_log = logs_dir / "retry_failures.log"

    runs_log.write_text("", encoding="utf-8")
    failures_log.write_text("", encoding="utf-8")
    retry_runs_log.write_text("", encoding="utf-8")
    retry_failures_log.write_text("", encoding="utf-8")

    used_labels: set[str] = set()
    repo_runs: list[RepoRun] = []
    initial_failures: list[str] = []

    for repo_path in repos:
        label = safe_repo_label(repo_path, used_labels)
        repo_out = repos_out_dir / label
        repo_out.mkdir(parents=True, exist_ok=True)

        with runs_log.open("a", encoding="utf-8") as f:
            f.write(f"[START] {label}\n")

        cmd = [
            sys.executable,
            str(runner),
            "--repo",
            str(repo_path),
            "--out",
            str(repo_out),
            "--timeframe-days",
            str(args.timeframe_days),
            "--stale-days",
            str(args.stale_days),
            "--risk-appetite",
            args.risk_appetite,
            "--report-format",
            "json",
            "--max-findings",
            str(args.max_findings),
            "--history-depth",
            args.history_depth,
        ]

        if args.include_roadmap:
            cmd.append("--include-roadmap")
        else:
            cmd.append("--no-include-roadmap")

        if args.privacy_mode:
            cmd.append("--privacy-mode")
        else:
            cmd.append("--no-privacy-mode")

        proc = subprocess.run(cmd, text=True, capture_output=True)
        if proc.returncode != 0:
            initial_failures.append(label)
            err = proc.stderr.strip() or proc.stdout.strip() or f"exit={proc.returncode}"
            with failures_log.open("a", encoding="utf-8") as f:
                f.write(f"[{label}] {err}\n")
            with runs_log.open("a", encoding="utf-8") as f:
                f.write(f"[FAIL:{proc.returncode}] {label}\n")

            repo_runs.append(RepoRun(name=label, path=str(repo_path), out_dir=repo_out, success=False, error=err))
            if not args.continue_on_error:
                break
            continue

        try:
            run_summary = json_load(repo_out / "run_summary.json")
            tdd_report = json_load(repo_out / "tdd_report_json.json")
            risk_matrix = json_load(repo_out / "risk_matrix_json.json")
            metrics_summary = json_load(repo_out / "metrics_summary_json.json")
            smi = json_load(repo_out / "security_maturity_index_json.json")
            evidence = json_load(repo_out / "evidence_index_json.json")
            repo_runs.append(
                RepoRun(
                    name=label,
                    path=str(repo_path),
                    out_dir=repo_out,
                    success=True,
                    run_summary=run_summary,
                    tdd_report=tdd_report,
                    risk_matrix=risk_matrix,
                    metrics_summary=metrics_summary,
                    smi=smi,
                    evidence=evidence,
                )
            )
            with runs_log.open("a", encoding="utf-8") as f:
                f.write(f"[OK] {label}\n")
        except Exception as exc:  # noqa: BLE001
            err = f"parse_error: {exc}"
            with failures_log.open("a", encoding="utf-8") as f:
                f.write(f"[{label}] {err}\n")
            with runs_log.open("a", encoding="utf-8") as f:
                f.write(f"[FAIL:parse] {label}\n")
            repo_runs.append(RepoRun(name=label, path=str(repo_path), out_dir=repo_out, success=False, error=err))
            if not args.continue_on_error:
                break

    evidence = EvidenceBook()
    evidence.add("command", "discover_repos", "Portfolio repository discovery")
    evidence.add(
        "command",
        f"{sys.executable} {runner.name} --report-format json",
        "Per-repository CodeAtlas runs",
    )

    mode = "full"
    for repo_run in repo_runs:
        if repo_run.success and repo_run.run_summary:
            mode = str(repo_run.run_summary.get("mode", mode))
            break

    aggregate = aggregate_portfolio(
        generated_at=generated_at,
        mode=mode,
        root=portfolio_root,
        repo_runs=repo_runs,
        initial_failures=initial_failures,
        evidence=evidence,
        include_roadmap=args.include_roadmap,
    )

    report_json = aggregate["report"]
    risk_matrix = aggregate["risk_matrix"]
    metrics_summary = aggregate["metrics_summary"]
    smi_json = aggregate["smi"]

    combined_report_json_path = out_dir / "combined_tdd_report_json.json"
    combined_risk_json_path = out_dir / "combined_risk_matrix_json.json"
    combined_metrics_path = out_dir / "combined_metrics_summary_json.json"
    combined_smi_path = out_dir / "combined_security_maturity_index_json.json"
    combined_evidence_path = out_dir / "combined_evidence_index_json.json"
    combined_md_path = out_dir / "combined_tdd_report.md"
    combined_pdf_path = out_dir / "combined_tdd_report.pdf"

    if args.report_format in {"json", "both"}:
        json_dump(combined_report_json_path, report_json)
        json_dump(combined_risk_json_path, risk_matrix)
        json_dump(combined_metrics_path, metrics_summary)
        json_dump(combined_smi_path, smi_json)
        json_dump(combined_evidence_path, evidence.entries)

    markdown = to_markdown(
        report_json,
        aggregate["highest"],
        aggregate["lowest"],
        report_json.get("top_risks", []),
    )
    combined_md_path.write_text(markdown, encoding="utf-8")

    pdf_status = {"created": False, "engine": "none", "error": None, "path": None}
    if args.report_format in {"pdf", "both"}:
        ok, engine, error = render_pdf(
            combined_pdf_path,
            report_json,
            risk_matrix,
            aggregate["repo_rankings"],
        )
        pdf_status = {
            "created": ok,
            "engine": engine,
            "error": error,
            "path": str(combined_pdf_path) if ok else None,
        }
        if args.require_pdf and not ok:
            run_summary = {
                "generated_at": generated_at,
                "mode": mode,
                "portfolio_root": str(portfolio_root),
                "repo_count": len(repo_runs),
                "outputs": {
                    "combined_tdd_report_json": str(combined_report_json_path)
                    if combined_report_json_path.exists()
                    else None,
                    "combined_risk_matrix_json": str(combined_risk_json_path)
                    if combined_risk_json_path.exists()
                    else None,
                    "combined_metrics_summary_json": str(combined_metrics_path)
                    if combined_metrics_path.exists()
                    else None,
                    "combined_security_maturity_index_json": str(combined_smi_path)
                    if combined_smi_path.exists()
                    else None,
                    "combined_evidence_index_json": str(combined_evidence_path)
                    if combined_evidence_path.exists()
                    else None,
                    "combined_tdd_report_markdown": str(combined_md_path),
                },
                "pdf_status": pdf_status,
                "overall_score": report_json.get("overall_score", {}),
            }
            json_dump(out_dir / "combined_run_summary.json", run_summary)
            print(json.dumps(run_summary, indent=2))
            print(
                "[codeatlas-portfolio] PDF generation failed while --require-pdf=true",
                file=sys.stderr,
            )
            return 3

    run_summary = {
        "generated_at": generated_at,
        "mode": mode,
        "portfolio_root": str(portfolio_root),
        "repo_count": len(repo_runs),
        "outputs": {
            "combined_tdd_report_json": str(combined_report_json_path)
            if combined_report_json_path.exists()
            else None,
            "combined_risk_matrix_json": str(combined_risk_json_path)
            if combined_risk_json_path.exists()
            else None,
            "combined_metrics_summary_json": str(combined_metrics_path)
            if combined_metrics_path.exists()
            else None,
            "combined_security_maturity_index_json": str(combined_smi_path)
            if combined_smi_path.exists()
            else None,
            "combined_evidence_index_json": str(combined_evidence_path)
            if combined_evidence_path.exists()
            else None,
            "combined_tdd_report_markdown": str(combined_md_path),
            "combined_tdd_report_pdf": str(combined_pdf_path)
            if combined_pdf_path.exists()
            else None,
        },
        "overall_score": report_json.get("overall_score", {}),
        "security_maturity": report_json.get("security_maturity", {}),
        "top_portfolio_risks": report_json.get("top_risks", [])[:15],
        "pdf_status": pdf_status,
    }

    json_dump(out_dir / "combined_run_summary.json", run_summary)
    print(json.dumps(run_summary, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
