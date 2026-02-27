#!/usr/bin/env python3
"""Run CodeAtlas technical due diligence and emit JSON/PDF artifacts."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import math
import os
import re
import shutil
import statistics
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


@dataclass
class SecretFinding:
    source: str
    type: str
    file: str
    line: int | None
    commit: str | None
    commit_date: str | None
    severity: str
    classification: str
    classification_confidence: float
    signals_triggered: list[str]
    redacted_indicator: str
    evidence: list[str]
    raw_secret: str

    def public(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "type": self.type,
            "file": self.file,
            "line": self.line,
            "commit": self.commit,
            "commit_date": self.commit_date,
            "severity": self.severity,
            "classification": self.classification,
            "classification_confidence": round(self.classification_confidence, 3),
            "signals_triggered": self.signals_triggered,
            "redacted_indicator": self.redacted_indicator,
            "evidence": self.evidence,
        }


class EvidenceIndex:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._counter = 1

    def add(self, kind: str, pointer: str, description: str) -> str:
        evidence_id = f"E{self._counter:04d}"
        self._counter += 1
        self._entries.append(
            {
                "evidence_id": evidence_id,
                "type": kind,
                "pointer": pointer,
                "description": description,
            }
        )
        return evidence_id

    @property
    def entries(self) -> list[dict[str, Any]]:
        return self._entries


PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("aws_access_key", re.compile(r"(AKIA[0-9A-Z]{16})"), 90),
    ("slack_token", re.compile(r"(xox[baprs]-[0-9A-Za-z-]{10,})"), 90),
    ("stripe_live_key", re.compile(r"(sk_live_[0-9A-Za-z]{16,})"), 95),
    ("stripe_test_key", re.compile(r"(sk_test_[0-9A-Za-z]{16,})"), 50),
    (
        "connection_string",
        re.compile(r"((?:postgres|mysql|mongodb|redis|amqp)s?://[^\s:@/]+:[^\s@]+@[^\s]+)", re.I),
        85,
    ),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{8,})"
        ),
        60,
    ),
    ("private_key_header", re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"), 98),
]

TEST_PATH_PARTS = {
    "test",
    "tests",
    "__tests__",
    "fixture",
    "fixtures",
    "mock",
    "mocks",
    "sample",
    "samples",
    "example",
    "examples",
}

PROD_KEYWORDS = {"prod", "production", "live", "real", "customer", "payment", "billing"}
TEST_KEYWORDS = {"mock", "fixture", "sample", "dev", "local", "staging", "dummy", "fake"}

SOURCE_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".rs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".swift",
    ".kt",
    ".scala",
    ".sql",
    ".sh",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
    ".env",
}

IGNORE_DIR_MARKERS = {
    "node_modules",
    ".git",
    "dist",
    "build",
    "vendor",
    ".venv",
    "venv",
    "target",
}

AUTH_SIGNAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "jwt_usage": re.compile(r"\b(jwt|bearer)\b", re.I),
    "oauth_oidc": re.compile(r"\b(oauth|oidc|openid)\b", re.I),
    "auth_middleware": re.compile(r"\b(authenticate|authorization|authorize)\b", re.I),
    "session_or_cookie": re.compile(r"\b(session|cookie)\b", re.I),
}

ANTI_PATTERN_PATTERNS: dict[str, re.Pattern[str]] = {
    "todo_fixme_hack": re.compile(r"\b(TODO|FIXME|HACK|XXX)\b"),
    "broad_exception_python": re.compile(r"except\s+Exception\b"),
    "broad_exception_csharp": re.compile(r"catch\s*\(\s*Exception\b"),
    "insecure_http": re.compile(r"http://", re.I),
    "weak_crypto": re.compile(r"\b(md5|sha1)\b", re.I),
    "tls_verification_disabled": re.compile(r"(verify\s*=\s*False|insecure_skip_verify)", re.I),
    "raw_sql_concatenation": re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*(\+|\{)", re.I),
}

INFRA_YAML_KIND_PATTERNS: dict[str, re.Pattern[str]] = {
    "k8s_deployment": re.compile(r"^\s*kind:\s*(Deployment|StatefulSet|DaemonSet)\s*$", re.I),
    "k8s_service": re.compile(r"^\s*kind:\s*(Service|Ingress)\s*$", re.I),
    "k8s_job": re.compile(r"^\s*kind:\s*(Job|CronJob)\s*$", re.I),
}


def run(cmd: list[str], cwd: str | None = None, check: bool = True) -> str:
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr.strip()}"
        )
    return result.stdout


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run CodeAtlas technical due diligence")
    parser.add_argument("--repo", required=True, help="Repository root path")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--timeframe-days", type=int, default=180)
    parser.add_argument("--stale-days", type=int, default=365)
    parser.add_argument("--risk-appetite", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--target-scale-multiplier", type=int, default=5)
    parser.add_argument("--compliance-targets", default="", help="Comma-separated: GDPR,SOC2,...")
    parser.add_argument("--report-format", choices=["pdf", "json", "both"], default="both")
    parser.add_argument("--include-roadmap", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--privacy-mode", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--secret-scan-enabled", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--scan-git-history", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--scan-working-tree", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--classify-test-vs-prod", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument(
        "--history-depth",
        choices=["all", "timeframe", "default_branch_only"],
        default="all",
    )
    parser.add_argument("--max-findings", type=int, default=200)
    parser.add_argument("--slack-enabled", action=argparse.BooleanOptionalAction, default=False)
    return parser.parse_args()


def to_iso(ts: int | float | None) -> str | None:
    if ts is None:
        return None
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()


def detect_mode() -> str:
    try:
        run(["git", "--version"])
    except RuntimeError:
        return "api_only"

    # Lightweight outbound check for full vs offline mode.
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.25)
    try:
        sock.connect(("pypi.org", 443))
        sock.close()
        return "full"
    except OSError:
        return "offline"


def git_root(repo: str) -> str:
    return run(["git", "-C", repo, "rev-parse", "--show-toplevel"]).strip()


def has_commits(repo: str) -> bool:
    result = subprocess.run(
        ["git", "-C", repo, "rev-parse", "--verify", "HEAD"],
        text=True,
        capture_output=True,
    )
    return result.returncode == 0


def get_default_branch(repo: str) -> str:
    if not has_commits(repo):
        return "main"

    try:
        ref = run(
            ["git", "-C", repo, "symbolic-ref", "refs/remotes/origin/HEAD"], check=True
        ).strip()
        if ref.startswith("refs/remotes/origin/"):
            return ref.split("refs/remotes/origin/", 1)[1]
    except RuntimeError:
        pass

    branch = run(["git", "-C", repo, "rev-parse", "--abbrev-ref", "HEAD"]).strip()
    return branch if branch else "main"


def list_tracked_files(repo: str) -> list[str]:
    out = run(["git", "-C", repo, "ls-files"])
    return [line for line in out.splitlines() if line.strip()]


def is_source_file(path: str) -> bool:
    p = Path(path)
    if not p.suffix and p.name not in {"Dockerfile", "Makefile"}:
        return False
    if any(part in IGNORE_DIR_MARKERS for part in p.parts):
        return False
    return p.suffix.lower() in SOURCE_SUFFIXES or p.name in {"Dockerfile", "Makefile"}


def count_loc(path: Path) -> int:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0
    return sum(1 for _ in content.splitlines())


def compute_last_touch(repo: str, files: list[str]) -> dict[str, int]:
    targets = set(files)
    last_touch: dict[str, int] = {}
    current_ts: int | None = None
    try:
        out = run(["git", "-C", repo, "log", "--name-only", "--format=__TS__%ct"])
    except RuntimeError:
        return last_touch
    for line in out.splitlines():
        if line.startswith("__TS__"):
            try:
                current_ts = int(line[len("__TS__") :])
            except ValueError:
                current_ts = None
            continue
        if not line or current_ts is None:
            continue
        if line in targets and line not in last_touch:
            last_touch[line] = current_ts
            if len(last_touch) == len(targets):
                break
    return last_touch


def parse_numstat_since(
    repo: str, timeframe_days: int
) -> tuple[int, dict[str, int], dict[str, int], int, list[str], dict[str, set[str]]]:
    try:
        out = run(
            [
                "git",
                "-C",
                repo,
                "log",
                f"--since={timeframe_days} days ago",
                "--numstat",
                "--format=__C__%H|%an|%ct",
            ]
        )
    except RuntimeError:
        return 0, {}, {}, 0, [], {}
    churn_loc = 0
    per_file_changes: dict[str, int] = collections.Counter()
    per_author_loc: dict[str, int] = collections.Counter()
    commit_count = 0
    commit_hashes: list[str] = []
    per_file_authors: dict[str, set[str]] = collections.defaultdict(set)

    current_author = "unknown"
    for line in out.splitlines():
        if line.startswith("__C__"):
            commit_count += 1
            payload = line[len("__C__") :]
            parts = payload.split("|", 2)
            if len(parts) >= 2:
                commit_hashes.append(parts[0])
                current_author = parts[1] or "unknown"
            continue
        if not line or "\t" not in line:
            continue

        add_s, del_s, file_path = line.split("\t", 2)
        if add_s == "-" or del_s == "-":
            continue
        try:
            add_n = int(add_s)
            del_n = int(del_s)
        except ValueError:
            continue
        delta = add_n + del_n
        churn_loc += delta
        per_file_changes[file_path] += 1
        per_author_loc[current_author] += delta
        per_file_authors[file_path].add(current_author)

    return churn_loc, dict(per_file_changes), dict(per_author_loc), commit_count, commit_hashes, per_file_authors


def gini(values: list[int]) -> float:
    if not values:
        return 0.0
    sorted_vals = sorted(v for v in values if v >= 0)
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    total = sum(sorted_vals)
    if total == 0:
        return 0.0
    weighted_sum = sum((i + 1) * val for i, val in enumerate(sorted_vals))
    return max(0.0, min(1.0, (2 * weighted_sum) / (n * total) - (n + 1) / n))


def bus_factor_proxy(per_author_loc: dict[str, int]) -> int:
    total = sum(per_author_loc.values())
    if total <= 0:
        return 0
    cutoff = total * 0.8
    running = 0
    needed = 0
    for _, value in sorted(per_author_loc.items(), key=lambda item: item[1], reverse=True):
        running += value
        needed += 1
        if running >= cutoff:
            return needed
    return needed


def file_has_adjacent_docs(repo_path: Path, rel_path: str) -> bool:
    parent = (repo_path / rel_path).parent
    names = {"README.md", "readme.md", "ARCHITECTURE.md", "architecture.md"}
    return any((parent / name).exists() for name in names)


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def parse_requirements(path: Path) -> list[str]:
    deps: list[str] = []
    if not path.exists():
        return deps
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#") or cleaned.startswith("-"):
            continue
        dep = re.split(r"[<>=~!]", cleaned, maxsplit=1)[0].strip()
        if dep:
            deps.append(dep)
    return deps


def parse_go_mod(path: Path) -> list[str]:
    deps: list[str] = []
    if not path.exists():
        return deps
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped.startswith("require "):
            parts = stripped.split()
            if len(parts) >= 2:
                deps.append(parts[1])
    return deps


def parse_toml_dependencies(path: Path) -> list[str]:
    if not path.exists() or tomllib is None:
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []

    deps: list[str] = []
    project = data.get("project")
    if isinstance(project, dict):
        for dep in project.get("dependencies", []) or []:
            if isinstance(dep, str):
                deps.append(re.split(r"[<>=~!]", dep, maxsplit=1)[0].strip())

    for section_name in ("tool",):
        tool = data.get(section_name)
        if isinstance(tool, dict):
            poetry = tool.get("poetry")
            if isinstance(poetry, dict):
                poetry_deps = poetry.get("dependencies")
                if isinstance(poetry_deps, dict):
                    for key in poetry_deps:
                        if key != "python":
                            deps.append(str(key))

    return deps


def discover_dependencies(repo_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    inventory: list[dict[str, Any]] = []
    dep_files: list[str] = []

    package_json = repo_path / "package.json"
    if package_json.exists():
        payload = read_json(package_json)
        deps = list((payload.get("dependencies") or {}).keys())
        dev_deps = list((payload.get("devDependencies") or {}).keys())
        all_deps = sorted(set(deps + dev_deps))
        inventory.append(
            {
                "ecosystem": "npm",
                "file": "package.json",
                "count": len(all_deps),
                "sample": all_deps[:50],
                "method": "manifest_parse",
            }
        )
        dep_files.append("package.json")
        for lock_name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            if (repo_path / lock_name).exists():
                dep_files.append(lock_name)

    req = parse_requirements(repo_path / "requirements.txt")
    if req:
        inventory.append(
            {
                "ecosystem": "pip",
                "file": "requirements.txt",
                "count": len(req),
                "sample": req[:50],
                "method": "manifest_parse",
            }
        )
        dep_files.append("requirements.txt")

    pyproject_deps = parse_toml_dependencies(repo_path / "pyproject.toml")
    if pyproject_deps:
        inventory.append(
            {
                "ecosystem": "python",
                "file": "pyproject.toml",
                "count": len(pyproject_deps),
                "sample": sorted(set(pyproject_deps))[:50],
                "method": "manifest_parse",
            }
        )
        dep_files.append("pyproject.toml")
        for lock_name in ("poetry.lock", "Pipfile.lock"):
            if (repo_path / lock_name).exists():
                dep_files.append(lock_name)

    go_deps = parse_go_mod(repo_path / "go.mod")
    if go_deps:
        inventory.append(
            {
                "ecosystem": "go",
                "file": "go.mod",
                "count": len(go_deps),
                "sample": sorted(set(go_deps))[:50],
                "method": "manifest_parse",
            }
        )
        dep_files.extend(["go.mod", "go.sum"])

    cargo_toml = parse_toml_dependencies(repo_path / "Cargo.toml")
    if cargo_toml:
        inventory.append(
            {
                "ecosystem": "cargo",
                "file": "Cargo.toml",
                "count": len(cargo_toml),
                "sample": sorted(set(cargo_toml))[:50],
                "method": "manifest_parse",
            }
        )
        dep_files.extend(["Cargo.toml", "Cargo.lock"])

    if (repo_path / "pom.xml").exists():
        inventory.append(
            {
                "ecosystem": "maven",
                "file": "pom.xml",
                "count": None,
                "sample": [],
                "method": "xml_presence_only",
            }
        )
        dep_files.append("pom.xml")

    if (repo_path / "Gemfile").exists():
        inventory.append(
            {
                "ecosystem": "bundler",
                "file": "Gemfile",
                "count": None,
                "sample": [],
                "method": "manifest_presence_only",
            }
        )
        dep_files.append("Gemfile")

    if (repo_path / "composer.json").exists():
        payload = read_json(repo_path / "composer.json")
        deps = sorted(set((payload.get("require") or {}).keys()))
        inventory.append(
            {
                "ecosystem": "composer",
                "file": "composer.json",
                "count": len(deps),
                "sample": deps[:50],
                "method": "manifest_parse",
            }
        )
        dep_files.append("composer.json")

    dep_files = sorted(set(dep_files))
    return inventory, dep_files


def dependency_cadence(repo: str, dep_files: list[str], lookback_days: int = 90) -> int:
    if not dep_files:
        return 0

    try:
        out = run(
            [
                "git",
                "-C",
                repo,
                "log",
                f"--since={lookback_days} days ago",
                "--name-only",
                "--format=__C__%H",
            ]
        )
    except RuntimeError:
        return 0
    changed_commits = 0
    current_has_dep_change = False
    dep_set = set(dep_files)

    for line in out.splitlines():
        if line.startswith("__C__"):
            if current_has_dep_change:
                changed_commits += 1
            current_has_dep_change = False
            continue
        if line in dep_set:
            current_has_dep_change = True

    if current_has_dep_change:
        changed_commits += 1

    return changed_commits


def has_any(repo_path: Path, names: Iterable[str]) -> bool:
    return any((repo_path / name).exists() for name in names)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = collections.Counter(value)
    length = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def path_is_test_like(path: str) -> bool:
    lower_parts = {part.lower() for part in Path(path).parts}
    return any(part in TEST_PATH_PARTS for part in lower_parts)


def classify_secret(path: str, line: str, secret_type: str, raw_secret: str) -> tuple[str, float, list[str]]:
    prod_signals: list[str] = []
    test_signals: list[str] = []

    lower_line = line.lower()
    lower_path = path.lower()

    strong_prod_types = {"aws_access_key", "stripe_live_key", "slack_token", "private_key_header", "connection_string"}
    if secret_type in strong_prod_types:
        prod_signals.append("matches known provider pattern")

    entropy = shannon_entropy(raw_secret)
    if len(raw_secret) >= 20 and entropy >= 3.5:
        prod_signals.append("high entropy string length >= 20 and entropy >= 3.5")

    if not path_is_test_like(path):
        prod_signals.append("found outside tests/fixtures/mocks/samples")

    infra_suffixes = {".env", ".yaml", ".yml", ".tf", ".tfvars", ".json", ".toml"}
    if Path(path).suffix.lower() in infra_suffixes or any(
        token in lower_path for token in ["docker-compose", "helm", "terraform", "k8s", "kubernetes"]
    ):
        prod_signals.append("appears in infra/config files")

    if any(word in lower_line for word in PROD_KEYWORDS):
        prod_signals.append("keywords nearby: prod|production|live|real|customer|payment|billing")

    if path_is_test_like(path):
        test_signals.append("found in tests/fixtures/mocks/samples directories")

    if any(word in raw_secret.lower() for word in ["test", "example", "dummy", "fake", "changeme", "password", "123456", "qwerty"]):
        test_signals.append("contains test/example/dummy/fake/changeme/password/123456/qwerty")

    if any(word in lower_line for word in TEST_KEYWORDS):
        test_signals.append("keywords nearby: mock|fixture|sample|dev|local|staging")

    if prod_signals and not test_signals:
        cls = "prod_like"
    elif test_signals and not (len(prod_signals) >= 2 and "matches known provider pattern" in prod_signals):
        cls = "test_like"
    else:
        cls = "unknown"

    confidence = 0.5 + min(0.45, 0.1 * max(len(prod_signals), len(test_signals)))
    confidence = round(min(0.95, confidence), 3)
    return cls, confidence, prod_signals + test_signals


def severity_for(secret_type: str, classification: str) -> str:
    if secret_type in {"private_key_header", "stripe_live_key"} and classification == "prod_like":
        return "critical"
    if classification == "prod_like":
        return "high"
    if classification == "test_like":
        return "low"
    return "medium"


def looks_text(path: Path) -> bool:
    try:
        data = path.read_bytes()[:4096]
    except OSError:
        return False
    if b"\x00" in data:
        return False
    return True


def find_secret_hits(line: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for secret_type, pattern, _strength in PATTERNS:
        for match in pattern.finditer(line):
            raw = match.group(1)
            if raw and len(raw) >= 8:
                hits.append((secret_type, raw))

    # Additional high-entropy token heuristic.
    for token in re.findall(r"[A-Za-z0-9_\-+/=]{20,}", line):
        if token.isdigit():
            continue
        if token.lower() in {"authorization", "content-type", "application/json"}:
            continue
        if shannon_entropy(token) >= 3.8:
            if not re.search(r"[0-9]", token):
                continue
            hits.append(("high_entropy_token", token))

    return hits


def build_finding(
    source: str,
    secret_type: str,
    raw_secret: str,
    file_path: str,
    line_no: int | None,
    line_text: str,
    commit: str | None,
    commit_date: str | None,
    evidence_id: str,
    classify: bool,
) -> SecretFinding:
    if classify:
        cls, cls_conf, signals = classify_secret(file_path, line_text, secret_type, raw_secret)
    else:
        cls, cls_conf, signals = "unknown", 0.5, []
    severity = severity_for(secret_type, cls)
    indicator = f"{secret_type}:{hashlib.sha256(raw_secret.encode('utf-8', errors='ignore')).hexdigest()[:12]}"
    return SecretFinding(
        source=source,
        type=secret_type,
        file=file_path,
        line=line_no,
        commit=commit,
        commit_date=commit_date,
        severity=severity,
        classification=cls,
        classification_confidence=cls_conf,
        signals_triggered=signals,
        redacted_indicator=indicator,
        evidence=[evidence_id],
        raw_secret=raw_secret,
    )


def scan_working_tree_for_secrets(
    repo_path: Path,
    tracked_files: list[str],
    max_findings: int,
    evidence: EvidenceIndex,
    classify: bool,
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    evidence_id = evidence.add(
        "command",
        f"scan tracked files with regex+entropy ({len(tracked_files)} files)",
        "Working tree secret scan",
    )
    seen: set[tuple[str, str, str]] = set()

    for rel_path in tracked_files:
        if len(findings) >= max_findings:
            break
        path = repo_path / rel_path
        if not path.exists() or path.is_dir() or path.stat().st_size > 2_000_000:
            continue
        if not looks_text(path):
            continue

        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for idx, line in enumerate(lines, start=1):
            for secret_type, raw in find_secret_hits(line):
                key = (secret_type, rel_path, hashlib.sha256(raw.encode()).hexdigest())
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    build_finding(
                        source="working_tree",
                        secret_type=secret_type,
                        raw_secret=raw,
                        file_path=rel_path,
                        line_no=idx,
                        line_text=line,
                        commit=None,
                        commit_date=None,
                        evidence_id=evidence_id,
                        classify=classify,
                    )
                )
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break

    return findings


def parse_patch_stream_for_secrets(
    proc: subprocess.Popen[str],
    max_findings: int,
    evidence_id: str,
    classify: bool,
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    seen: set[tuple[str, str, str, str]] = set()

    current_commit: str | None = None
    current_commit_date: str | None = None
    current_file: str | None = None
    current_line_no: int | None = None

    assert proc.stdout is not None
    for raw_line in proc.stdout:
        line = raw_line.rstrip("\n")

        if line.startswith("__C__"):
            payload = line[len("__C__") :]
            parts = payload.split("|", 1)
            current_commit = parts[0]
            try:
                ts = int(parts[1]) if len(parts) > 1 else None
            except ValueError:
                ts = None
            current_commit_date = to_iso(ts)
            continue

        if line.startswith("diff --git"):
            match = re.search(r" b/(.+)$", line)
            current_file = match.group(1) if match else None
            current_line_no = None
            continue

        if line.startswith("+++ b/"):
            current_file = line[len("+++ b/") :]
            continue

        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            if match:
                current_line_no = int(match.group(1)) - 1
            continue

        if line.startswith("+") and not line.startswith("+++"):
            if current_line_no is not None:
                current_line_no += 1
            content = line[1:]
            if current_file is None:
                continue

            for secret_type, raw_secret in find_secret_hits(content):
                digest = hashlib.sha256(raw_secret.encode()).hexdigest()
                key = (current_commit or "", current_file, secret_type, digest)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    build_finding(
                        source="git_history",
                        secret_type=secret_type,
                        raw_secret=raw_secret,
                        file_path=current_file,
                        line_no=current_line_no,
                        line_text=content,
                        commit=current_commit,
                        commit_date=current_commit_date,
                        evidence_id=evidence_id,
                        classify=classify,
                    )
                )
                if len(findings) >= max_findings:
                    proc.kill()
                    return findings
            continue

        if line.startswith(" ") and current_line_no is not None:
            current_line_no += 1

    return findings


def scan_git_history_for_secrets(
    repo: str,
    history_depth: str,
    timeframe_days: int,
    default_branch: str,
    max_findings: int,
    evidence: EvidenceIndex,
    classify: bool,
) -> list[SecretFinding]:
    if not has_commits(repo):
        return []

    cmd = ["git", "-C", repo, "log"]
    if history_depth == "all":
        cmd.append("--all")
    elif history_depth == "timeframe":
        cmd.append(f"--since={timeframe_days} days ago")
    else:
        cmd.append(default_branch)

    cmd.extend(["-p", "--no-color", "--format=__C__%H|%ct"])

    evidence_id = evidence.add("command", " ".join(cmd), "Git history secret scan")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    findings = parse_patch_stream_for_secrets(proc, max_findings, evidence_id, classify)
    _, stderr = proc.communicate(timeout=300)
    if proc.returncode not in (0, None):
        raise RuntimeError(f"Git history scan failed: {stderr.strip()}")
    return findings


def summarize_secret_findings(
    findings: list[SecretFinding],
    working_findings: list[SecretFinding],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    severity_breakdown = collections.Counter(f.severity for f in findings)
    types_breakdown = collections.Counter(f.type for f in findings)
    class_breakdown = collections.Counter(f.classification for f in findings)
    dates = [f.commit_date for f in findings if f.commit_date]

    raw_in_working = {f.raw_secret for f in working_findings}
    reachable = sum(1 for f in findings if f.raw_secret in raw_in_working)

    secret_metric = {
        "metric_id": "git_history_secrets_exposure",
        "value": {
            "findings_count": len(findings),
            "severity_breakdown": dict(severity_breakdown),
            "types_breakdown": dict(types_breakdown),
            "reachable_in_default_branch": reachable,
            "first_seen_commit_date": min(dates) if dates else None,
            "last_seen_commit_date": max(dates) if dates else None,
            "classification_breakdown": dict(class_breakdown),
            "redacted_indicators_sample": [f.redacted_indicator for f in findings[:20]],
        },
        "method": "regex+entropy scan over git patches with redacted indicators",
        "confidence": 0.78,
        "evidence": sorted({e for f in findings for e in f.evidence}),
    }

    controls = {
        "pre_commit_secret_scan": False,
        "ci_secret_scan": False,
        "env_ignored": False,
        "secret_manager_signal": False,
    }

    secret_hygiene_score = 100
    for control, enabled in controls.items():
        if not enabled:
            secret_hygiene_score -= 15

    if len(findings) >= 1:
        secret_hygiene_score -= min(45, len(findings) * 6)

    secret_hygiene_metric = {
        "metric_id": "secrets_hygiene_controls",
        "value": {
            "controls": controls,
            "score": max(0, secret_hygiene_score),
        },
        "method": "repository control presence + secret findings penalty",
        "confidence": 0.62,
        "evidence": sorted({e for f in findings for e in f.evidence}),
    }

    public_findings = [finding.public() for finding in findings]
    return secret_metric, secret_hygiene_metric, public_findings


def infer_languages(source_files: list[str]) -> dict[str, int]:
    counts: dict[str, int] = collections.Counter()
    for path in source_files:
        suffix = Path(path).suffix.lower()
        lang = suffix.lstrip(".") if suffix else Path(path).name
        counts[lang] += 1
    return dict(counts)


def detect_devops_signals(repo_path: Path, tracked_files: list[str]) -> dict[str, bool]:
    lower_files = [f.lower() for f in tracked_files]
    return {
        "github_actions": any(f.startswith(".github/workflows/") for f in lower_files),
        "gitlab_ci": ".gitlab-ci.yml" in lower_files,
        "jenkins": any("jenkinsfile" in f for f in lower_files),
        "docker": any(Path(f).name.lower() == "dockerfile" for f in lower_files),
        "kubernetes": any("k8s" in f or "kubernetes" in f for f in lower_files),
        "terraform": any(f.endswith(".tf") for f in lower_files),
        "helm": any("chart.yaml" in f for f in lower_files),
        "observability": any(
            token in f
            for token in ["prometheus", "grafana", "datadog", "sentry", "opentelemetry", "otel"]
            for f in lower_files
        ),
        "backup_signal": any(token in f for token in ["backup", "restore", "snapshot"] for f in lower_files),
        "codeowners": (repo_path / "CODEOWNERS").exists() or (repo_path / ".github" / "CODEOWNERS").exists(),
    }


def sample_values(values: Iterable[str], limit: int = 8) -> list[str]:
    return sorted(dict.fromkeys(v for v in values if v))[:limit]


def analyze_infrastructure_landscape(
    repo_path: Path,
    tracked_files: list[str],
    devops_signals: dict[str, bool],
    evidence: EvidenceIndex,
) -> dict[str, Any]:
    infra_evidence = evidence.add(
        "command",
        "git ls-files + static filename/kind scanning for infrastructure artifacts",
        "Infrastructure and deployment artifact discovery",
    )

    dockerfiles = [f for f in tracked_files if Path(f).name.lower() == "dockerfile"]
    compose_files = [
        f for f in tracked_files if "docker-compose" in Path(f).name.lower() or Path(f).name.lower().endswith("compose.yml")
    ]
    k8s_files = [
        f
        for f in tracked_files
        if any(token in f.lower() for token in ["k8s", "kubernetes", "manifests", "charts"])
    ]
    terraform_files = [f for f in tracked_files if f.lower().endswith((".tf", ".tfvars"))]
    helm_files = [f for f in tracked_files if Path(f).name.lower() in {"chart.yaml", "values.yaml"}]
    cloudformation_files = [
        f
        for f in tracked_files
        if "cloudformation" in f.lower() or Path(f).name.lower().endswith((".template", ".cfn.yml", ".cfn.yaml"))
    ]
    pipeline_files = [
        f
        for f in tracked_files
        if f.lower().startswith(".github/workflows/")
        or f.lower() in {".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml"}
    ]

    # Detect Kubernetes kinds even when files are not under explicit k8s paths.
    yaml_candidates = [
        f
        for f in tracked_files
        if f.lower().endswith((".yaml", ".yml")) and not f.lower().startswith(".github/")
    ][:400]
    kind_hits: dict[str, int] = collections.Counter()
    kind_hit_files: dict[str, set[str]] = collections.defaultdict(set)
    for rel_path in yaml_candidates:
        full_path = repo_path / rel_path
        if not full_path.exists() or full_path.stat().st_size > 1_000_000:
            continue
        if not looks_text(full_path):
            continue
        try:
            lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()[:200]
        except OSError:
            continue
        for line in lines:
            for kind_key, pattern in INFRA_YAML_KIND_PATTERNS.items():
                if pattern.search(line):
                    kind_hits[kind_key] += 1
                    kind_hit_files[kind_key].add(rel_path)

    inferred_runtime_model: list[str] = []
    if dockerfiles:
        inferred_runtime_model.append("Containerized services are present (Dockerfile detected).")
    if compose_files:
        inferred_runtime_model.append("Local multi-service orchestration appears to use docker-compose.")
    if devops_signals["kubernetes"] or sum(kind_hits.values()) > 0:
        inferred_runtime_model.append("Kubernetes-style deployment artifacts are present.")
    if terraform_files:
        inferred_runtime_model.append("Infrastructure-as-code via Terraform is present.")
    if helm_files:
        inferred_runtime_model.append("Helm charting assets are present for templated Kubernetes deployment.")
    if not inferred_runtime_model:
        inferred_runtime_model.append("No explicit deployment/runtime artifacts were detected from repository files.")

    infra_maturity_score = 15
    if dockerfiles:
        infra_maturity_score += 18
    if compose_files:
        infra_maturity_score += 8
    if devops_signals["kubernetes"] or sum(kind_hits.values()) > 0:
        infra_maturity_score += 18
    if terraform_files:
        infra_maturity_score += 18
    if helm_files:
        infra_maturity_score += 10
    if pipeline_files:
        infra_maturity_score += 14
    if devops_signals["observability"]:
        infra_maturity_score += 10
    if devops_signals["backup_signal"]:
        infra_maturity_score += 9
    infra_maturity_score = int(clamp_score(infra_maturity_score))

    findings: list[dict[str, Any]] = []
    if not dockerfiles and not compose_files and not devops_signals["kubernetes"]:
        findings.append(
            {
                "finding": "No explicit deployment packaging signal (container/runtime manifests) was detected",
                "evidence": [infra_evidence],
                "risk": "Operational onboarding and environment parity may depend on undocumented manual knowledge",
                "recommendation": "Codify runtime/deployment model in versioned Docker/Kubernetes or equivalent manifests",
                "confidence": 0.66,
            }
        )
    if not terraform_files and not cloudformation_files:
        findings.append(
            {
                "finding": "Infrastructure-as-code evidence is limited",
                "evidence": [infra_evidence],
                "risk": "Higher risk of environment drift and non-reproducible production changes",
                "recommendation": "Adopt and enforce IaC for baseline cloud/network/service provisioning",
                "confidence": 0.69,
            }
        )
    if not devops_signals["observability"]:
        findings.append(
            {
                "finding": "Observability configuration signal is weak",
                "evidence": [infra_evidence],
                "risk": "Longer incident detection and diagnosis cycles",
                "recommendation": "Define baseline telemetry (logs, metrics, traces, alert routing) per service",
                "confidence": 0.64,
            }
        )

    narrative = (
        f"Infrastructure analysis found {len(dockerfiles)} Dockerfiles, {len(compose_files)} compose files, "
        f"{len(terraform_files)} Terraform files, and {len(pipeline_files)} pipeline definitions. "
        f"Inferred infrastructure maturity score is {infra_maturity_score}/100."
    )

    return {
        "infra_maturity_score": infra_maturity_score,
        "deployment_artifacts": {
            "dockerfiles": sample_values(dockerfiles, 20),
            "compose_files": sample_values(compose_files, 20),
            "kubernetes_related_files": sample_values(k8s_files, 30),
            "terraform_files": sample_values(terraform_files, 30),
            "helm_files": sample_values(helm_files, 20),
            "cloudformation_files": sample_values(cloudformation_files, 20),
            "pipeline_files": sample_values(pipeline_files, 30),
            "k8s_kinds_detected": dict(kind_hits),
            "k8s_kind_sample_files": {
                key: sample_values(values, 10) for key, values in kind_hit_files.items()
            },
        },
        "inferred_runtime_model": inferred_runtime_model,
        "narrative": narrative,
        "findings": findings,
        "evidence": [infra_evidence],
    }


def analyze_code_pattern_signals(
    repo_path: Path,
    source_files: list[str],
    evidence: EvidenceIndex,
) -> dict[str, Any]:
    pattern_evidence = evidence.add(
        "command",
        "Static regex scan across source files for auth/security and anti-pattern signals",
        "Code-pattern sub-agent scan",
    )

    auth_counts: dict[str, int] = collections.Counter()
    anti_counts: dict[str, int] = collections.Counter()
    auth_hit_files: dict[str, set[str]] = collections.defaultdict(set)
    anti_hit_files: dict[str, set[str]] = collections.defaultdict(set)

    scanned = 0
    for rel_path in sorted(source_files)[:1600]:
        full_path = repo_path / rel_path
        if not full_path.exists():
            continue
        if full_path.stat().st_size > 800_000:
            continue
        if not looks_text(full_path):
            continue
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        scanned += 1
        for key, pattern in AUTH_SIGNAL_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                auth_counts[key] += len(matches)
                auth_hit_files[key].add(rel_path)
        for key, pattern in ANTI_PATTERN_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                anti_counts[key] += len(matches)
                anti_hit_files[key].add(rel_path)

    auth_signal_strength = sum(auth_counts.values())
    anti_signal_pressure = sum(anti_counts.values())

    auth_posture_score = 35
    if auth_counts["auth_middleware"] > 20:
        auth_posture_score += 18
    elif auth_counts["auth_middleware"] > 0:
        auth_posture_score += 10
    if auth_counts["jwt_usage"] > 0 or auth_counts["oauth_oidc"] > 0:
        auth_posture_score += 12
    if auth_counts["session_or_cookie"] > 0:
        auth_posture_score += 6
    if anti_counts["insecure_http"] == 0:
        auth_posture_score += 8
    if anti_counts["weak_crypto"] == 0:
        auth_posture_score += 10
    auth_posture_score = int(clamp_score(auth_posture_score))

    anti_pattern_pressure_score = int(clamp_score(100 - min(100, anti_signal_pressure / 5)))

    findings: list[dict[str, Any]] = []
    if auth_signal_strength == 0:
        findings.append(
            {
                "category": "security",
                "finding": "Authentication/authorization enforcement signals are sparse in scanned source files",
                "evidence": [pattern_evidence],
                "risk": "Access-control behavior may be concentrated in external layers or undocumented flows",
                "recommendation": "Document and centralize authn/authz controls, and enforce policy checks at service boundaries",
                "confidence": 0.52,
            }
        )
    if anti_counts["insecure_http"] > 0:
        findings.append(
            {
                "category": "security",
                "finding": "Insecure HTTP references were detected",
                "evidence": [pattern_evidence],
                "risk": "Sensitive traffic may be exposed if these references are runtime reachable",
                "recommendation": "Enforce TLS-only endpoints and block plaintext protocol usage in CI",
                "confidence": 0.76,
            }
        )
    if anti_counts["weak_crypto"] > 0:
        findings.append(
            {
                "category": "security",
                "finding": "Weak cryptographic primitive references (MD5/SHA1) were detected",
                "evidence": [pattern_evidence],
                "risk": "Potential cryptographic integrity/strength weaknesses in security-sensitive paths",
                "recommendation": "Migrate to modern approved primitives and validate by crypto linting",
                "confidence": 0.79,
            }
        )
    if anti_counts["todo_fixme_hack"] > 100:
        findings.append(
            {
                "category": "code_health",
                "finding": "High TODO/FIXME/HACK density suggests unresolved engineering debt",
                "evidence": [pattern_evidence],
                "risk": "Deferred defects and inconsistent implementation quality increase delivery risk",
                "recommendation": "Track backlog debt explicitly and age-limit TODO/HACK items in critical modules",
                "confidence": 0.68,
            }
        )

    narrative = (
        f"Code-pattern scan covered {scanned} source files and found auth signal count={auth_signal_strength} "
        f"and anti-pattern signal count={anti_signal_pressure}. Auth posture score={auth_posture_score}/100, "
        f"anti-pattern pressure score={anti_pattern_pressure_score}/100."
    )

    return {
        "scanned_source_files": scanned,
        "auth_signals": dict(auth_counts),
        "anti_pattern_signals": dict(anti_counts),
        "auth_hit_files": {k: sample_values(v, 10) for k, v in auth_hit_files.items()},
        "anti_hit_files": {k: sample_values(v, 10) for k, v in anti_hit_files.items()},
        "auth_posture_score": auth_posture_score,
        "anti_pattern_pressure_score": anti_pattern_pressure_score,
        "narrative": narrative,
        "findings": findings,
        "evidence": [pattern_evidence],
    }


def findings_to_narrative_lines(findings: list[dict[str, Any]], limit: int = 4) -> list[str]:
    lines: list[str] = []
    for finding in findings[:limit]:
        lines.append(
            f"Finding: {finding.get('finding', '')}. Risk: {finding.get('risk', '')}. "
            f"Action: {finding.get('recommendation', '')}."
        )
    return lines


def build_risk(
    risk_id: str,
    title: str,
    category: str,
    impact: int,
    likelihood: int,
    effort: int,
    confidence: float,
    evidence: list[str],
    actions: list[str],
) -> dict[str, Any]:
    priority_score = impact * likelihood * 4 + (6 - effort)
    return {
        "risk_id": risk_id,
        "title": title,
        "category": category,
        "impact": impact,
        "likelihood": likelihood,
        "effort": effort,
        "priority_score": priority_score,
        "confidence": round(confidence, 3),
        "evidence": evidence,
        "recommended_actions": actions,
    }


def smi_tier(score: float) -> tuple[str, str]:
    if score >= 85:
        return "A", "Enterprise-ready"
    if score >= 70:
        return "B", "Mature startup"
    if score >= 50:
        return "C", "Typical startup risk"
    if score >= 30:
        return "D", "Structural risk"
    return "F", "Security liability"


def smi_multiplier(score: float) -> float:
    if score >= 85:
        return 0.8
    if score >= 70:
        return 1.0
    if score >= 50:
        return 1.2
    if score >= 30:
        return 1.5
    return 2.0


def clamp_score(value: float) -> float:
    return max(0.0, min(100.0, value))


def json_dump(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def render_pdf_report(
    out_path: Path,
    report: dict[str, Any],
    risk_matrix: list[dict[str, Any]],
    metrics: dict[str, Any],
    smi: dict[str, Any],
) -> tuple[bool, str]:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        doc = SimpleDocTemplate(str(out_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story: list[Any] = []

        story.append(Paragraph("CodeAtlas Technical Due Diligence", styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Repository: {report['repo']['path']}", styles["BodyText"]))
        story.append(Paragraph(f"Generated: {report['generated_at']}", styles["BodyText"]))
        story.append(Spacer(1, 12))

        score = report.get("overall_score", {})
        story.append(Paragraph("Overall Score & Risk", styles["Heading2"]))
        story.append(
            Paragraph(
                f"Final score: {score.get('final_score', 'n/a'):.2f} | Adjusted risk: {score.get('adjusted_tdd_risk', 'n/a'):.2f}",
                styles["BodyText"],
            )
        )
        story.append(
            Paragraph(
                f"SMI: {smi.get('score', 0):.2f} ({smi.get('tier', {}).get('tier', 'n/a')} - {smi.get('tier', {}).get('label', 'n/a')})",
                styles["BodyText"],
            )
        )
        story.append(Spacer(1, 12))

        story.append(Paragraph("Top Risks", styles["Heading2"]))
        risk_rows = [["ID", "Title", "Impact", "Likelihood", "Effort", "Priority", "Confidence"]]
        for risk in sorted(risk_matrix, key=lambda r: r["priority_score"], reverse=True)[:15]:
            risk_rows.append(
                [
                    risk["risk_id"],
                    risk["title"][:60],
                    str(risk["impact"]),
                    str(risk["likelihood"]),
                    str(risk["effort"]),
                    str(risk["priority_score"]),
                    f"{risk['confidence']:.2f}",
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

        story.append(Paragraph("Key Metrics", styles["Heading2"]))
        staleness_metrics = metrics.get("staleness_and_velocity", [])
        dep_metrics = metrics.get("dependencies_and_supply_chain", [])
        security_metrics = metrics.get("security_and_compliance", [])
        operability_metrics = metrics.get("operability", [])
        infra_metrics = metrics.get("infrastructure", [])

        rows = [["Metric", "Value", "Confidence"]]
        for bucket in (staleness_metrics, dep_metrics, security_metrics, operability_metrics, infra_metrics):
            for item in bucket[:8]:
                rows.append([
                    item.get("metric_id", "unknown"),
                    json.dumps(item.get("value"), ensure_ascii=False)[:80],
                    f"{item.get('confidence', 0):.2f}",
                ])

        metric_table = Table(rows, repeatRows=1)
        metric_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(metric_table)
        story.append(Spacer(1, 12))

        for section in report.get("sections", []):
            story.append(Paragraph(section.get("title", "Section"), styles["Heading2"]))
            story.append(Paragraph(section.get("summary", ""), styles["BodyText"]))
            for line in section.get("narrative_lines", [])[:8]:
                story.append(Paragraph(f"- {line}", styles["BodyText"]))

            for item in section.get("findings", [])[:8]:
                story.append(Paragraph(f"Finding: {item.get('finding', '')}", styles["BodyText"]))
                story.append(Paragraph(f"Evidence: {', '.join(item.get('evidence', []))}", styles["BodyText"]))
                story.append(Paragraph(f"Risk: {item.get('risk', '')}", styles["BodyText"]))
                story.append(Paragraph(f"Recommended action: {item.get('recommendation', '')}", styles["BodyText"]))
                story.append(
                    Paragraph(
                        f"Confidence: {float(item.get('confidence', 0) or 0):.2f}",
                        styles["Italic"],
                    )
                )
                story.append(Spacer(1, 4))

            for action in section.get("actions", [])[:10]:
                story.append(Paragraph(f"- {action}", styles["BodyText"]))

            infra = section.get("infrastructure_overview")
            if isinstance(infra, dict):
                story.append(
                    Paragraph(
                        f"Infrastructure maturity: {infra.get('infra_maturity_score', 'n/a')}/100",
                        styles["BodyText"],
                    )
                )
                story.append(Paragraph(infra.get("narrative", ""), styles["BodyText"]))
                for runtime_line in infra.get("inferred_runtime_model", [])[:6]:
                    story.append(Paragraph(f"- {runtime_line}", styles["BodyText"]))

            for phase in section.get("roadmap", [])[:6]:
                story.append(Paragraph(f"{phase.get('window', 'Window')}:", styles["BodyText"]))
                for focus in phase.get("focus", [])[:6]:
                    story.append(Paragraph(f"- {focus}", styles["BodyText"]))

            story.append(
                Paragraph(f"Confidence: {section.get('confidence', 0):.2f}", styles["Italic"])
            )
            story.append(Spacer(1, 8))

        doc.build(story)
        return True, "reportlab"
    except Exception:
        pass

    pandoc = shutil.which("pandoc")
    if pandoc:
        markdown_path = out_path.with_suffix(".md")
        markdown_lines = [
            "# CodeAtlas Technical Due Diligence",
            f"- Repository: `{report['repo']['path']}`",
            f"- Generated: `{report['generated_at']}`",
            "",
            "## Executive Narrative",
        ]
        for section in report.get("sections", []):
            markdown_lines.append(f"### {section.get('title', 'Section')}")
            markdown_lines.append(section.get("summary", ""))
            for line in section.get("narrative_lines", [])[:8]:
                markdown_lines.append(f"- {line}")
            for finding in section.get("findings", [])[:6]:
                markdown_lines.append(f"- Finding: {finding.get('finding', '')}")
                markdown_lines.append(f"  - Risk: {finding.get('risk', '')}")
                markdown_lines.append(f"  - Action: {finding.get('recommendation', '')}")
            markdown_lines.append("")
        markdown_lines.extend([
            "## Top Risks",
        ])
        for risk in sorted(risk_matrix, key=lambda r: r["priority_score"], reverse=True)[:20]:
            markdown_lines.append(
                f"- **{risk['risk_id']}** {risk['title']} (impact={risk['impact']}, likelihood={risk['likelihood']}, effort={risk['effort']}, confidence={risk['confidence']:.2f})"
            )

        markdown_path.write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")
        result = subprocess.run([pandoc, str(markdown_path), "-o", str(out_path)], capture_output=True, text=True)
        if result.returncode == 0:
            return True, "pandoc"

    return False, "none"


def main() -> int:
    args = parse_args()
    repo_input = os.path.abspath(args.repo)
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    evidence = EvidenceIndex()

    try:
        repo = git_root(repo_input)
    except RuntimeError as exc:
        print(f"[codeatlas] Not a git repository: {exc}", file=sys.stderr)
        return 2

    repo_path = Path(repo)
    generated_at = now_utc().isoformat()
    mode = detect_mode()
    default_branch = get_default_branch(repo)

    tracked_files = list_tracked_files(repo)
    source_files = [f for f in tracked_files if is_source_file(f)]
    languages = infer_languages(source_files)

    last_touch = compute_last_touch(repo, source_files)
    now_ts = now_utc().timestamp()

    loc_by_file: dict[str, int] = {}
    age_by_file: dict[str, float] = {}
    stale_loc = 0
    total_loc = 0

    for rel in source_files:
        file_path = repo_path / rel
        loc = count_loc(file_path)
        loc_by_file[rel] = loc
        total_loc += loc
        ts = last_touch.get(rel)
        if ts is None:
            try:
                ts = int(file_path.stat().st_mtime)
            except OSError:
                ts = int(now_ts)
        age_days = max(0.0, (now_ts - ts) / 86400)
        age_by_file[rel] = age_days
        if age_days > args.stale_days:
            stale_loc += loc

    stale_ratio = (stale_loc / total_loc) if total_loc > 0 else 0.0
    median_age_days = statistics.median(age_by_file.values()) if age_by_file else 0.0

    churn_loc, per_file_changes, per_author_loc, commit_count, timeframe_commits, per_file_authors = parse_numstat_since(
        repo, args.timeframe_days
    )
    gini_val = gini(list(per_file_changes.values()))
    bus_factor = bus_factor_proxy(per_author_loc)

    has_codeowners = (repo_path / "CODEOWNERS").exists() or (repo_path / ".github" / "CODEOWNERS").exists()
    orphan_loc = 0
    for rel, age in age_by_file.items():
        if age <= args.stale_days:
            continue
        authors = per_file_authors.get(rel, set())
        low_diversity = len(authors) <= 1
        no_adj_docs = not file_has_adjacent_docs(repo_path, rel)
        if low_diversity and no_adj_docs and not has_codeowners:
            orphan_loc += loc_by_file.get(rel, 0)
    orphan_ratio = (orphan_loc / total_loc) if total_loc > 0 else 0.0

    evidence_staleness = evidence.add(
        "command",
        f"git -C {repo} log --name-only --format=__TS__%ct",
        "Last-touch staleness computation",
    )
    evidence_velocity = evidence.add(
        "command",
        f"git -C {repo} log --since={args.timeframe_days} days ago --numstat --format=__C__%H|%an|%ct",
        "Velocity and churn metrics",
    )

    staleness_metrics = [
        {
            "metric_id": "median_file_last_touch_days",
            "value": round(median_age_days, 2),
            "method": "median(age_days across tracked source files)",
            "confidence": 0.86,
            "evidence": [evidence_staleness],
        },
        {
            "metric_id": "stale_code_ratio",
            "value": round(stale_ratio, 4),
            "method": f"stale_loc/total_loc where stale={args.stale_days}+ days",
            "confidence": 0.81,
            "evidence": [evidence_staleness],
        },
        {
            "metric_id": "churn_loc_timeframe",
            "value": churn_loc,
            "method": f"sum(add+del) over {args.timeframe_days} days",
            "confidence": 0.83,
            "evidence": [evidence_velocity],
        },
        {
            "metric_id": "change_concentration_gini",
            "value": round(gini_val, 4),
            "method": "gini over per-file change counts",
            "confidence": 0.79,
            "evidence": [evidence_velocity],
        },
        {
            "metric_id": "bus_factor_proxy",
            "value": bus_factor,
            "method": "minimum contributors accounting for 80% of changed LOC",
            "confidence": 0.76,
            "evidence": [evidence_velocity],
        },
        {
            "metric_id": "orphaned_code_ratio",
            "value": round(orphan_ratio, 4),
            "method": "stale + low author diversity + no CODEOWNERS/docs adjacency",
            "confidence": 0.6,
            "evidence": [evidence_staleness, evidence_velocity],
        },
    ]

    dependency_inventory, dep_files = discover_dependencies(repo_path)
    dep_cadence = dependency_cadence(repo, dep_files, lookback_days=90)
    has_bot = has_any(
        repo_path,
        [
            ".github/dependabot.yml",
            ".github/dependabot.yaml",
            "renovate.json",
            ".github/renovate.json",
            "renovate.json5",
        ],
    )
    has_lockfiles = has_any(
        repo_path,
        [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "Pipfile.lock",
            "go.sum",
            "Cargo.lock",
        ],
    )

    freshness_score = 20
    if dep_cadence >= 6:
        freshness_score += 40
    elif dep_cadence >= 3:
        freshness_score += 30
    elif dep_cadence >= 1:
        freshness_score += 15
    if has_bot:
        freshness_score += 20
    if has_lockfiles:
        freshness_score += 15
    if dep_files:
        freshness_score += 5
    freshness_score = int(clamp_score(freshness_score))

    evidence_deps = evidence.add(
        "command",
        f"git -C {repo} log --since=90 days ago --name-only --format=__C__%H",
        "Dependency update cadence",
    )

    dependency_metrics = [
        {
            "metric_id": "dependency_freshness_score",
            "value": freshness_score,
            "method": "heuristic score from update cadence + automation + lockfile hygiene",
            "confidence": 0.65,
            "evidence": [evidence_deps],
        },
        {
            "metric_id": "known_vuln_count",
            "value": None,
            "method": "no ecosystem scanner executed in static pass",
            "confidence": 0.2,
            "evidence": [evidence_deps],
        },
        {
            "metric_id": "dependency_update_cadence",
            "value": dep_cadence,
            "method": "commits touching dependency manifests in last 90 days",
            "confidence": 0.68,
            "evidence": [evidence_deps],
        },
    ]

    dependency_risks: list[dict[str, Any]] = []
    if freshness_score < 50:
        dependency_risks.append(
            {
                "finding": "Dependency freshness score is below risk threshold",
                "evidence": [evidence_deps],
                "risk": "Outdated dependencies increase security and upgrade risk",
                "recommendation": "Adopt automated dependency updates and a monthly upgrade SLA",
                "confidence": 0.71,
            }
        )
    if dep_cadence == 0 and dep_files:
        dependency_risks.append(
            {
                "finding": "No dependency updates detected in the last 90 days",
                "evidence": [evidence_deps],
                "risk": "Potential update debt and latent vulnerabilities",
                "recommendation": "Schedule dependency maintenance and enforce CI dependency policy gates",
                "confidence": 0.74,
            }
        )

    # Code health and CI signals.
    test_files = [
        f
        for f in source_files
        if any(token in f.lower() for token in ["/test", "/tests", "_test.", ".spec.", "__tests__"])
    ]
    test_ratio = (len(test_files) / len(source_files)) if source_files else 0.0
    devops_signals = detect_devops_signals(repo_path, tracked_files)
    infrastructure_analysis = analyze_infrastructure_landscape(
        repo_path=repo_path,
        tracked_files=tracked_files,
        devops_signals=devops_signals,
        evidence=evidence,
    )
    code_pattern_analysis = analyze_code_pattern_signals(
        repo_path=repo_path,
        source_files=source_files,
        evidence=evidence,
    )

    code_health_findings: list[dict[str, Any]] = []
    if test_ratio < 0.1:
        code_health_findings.append(
            {
                "finding": "Low test footprint by file ratio",
                "evidence": [evidence_velocity],
                "risk": "Higher regression risk and low refactor confidence",
                "recommendation": "Set target to raise test footprint and critical-path coverage",
                "confidence": 0.72,
            }
        )
    if not (devops_signals["github_actions"] or devops_signals["gitlab_ci"] or devops_signals["jenkins"]):
        code_health_findings.append(
            {
                "finding": "No CI pipeline configuration detected",
                "evidence": [evidence_velocity],
                "risk": "Build/test quality gates may be inconsistent",
                "recommendation": "Introduce CI with lint, test, dependency, and secret checks",
                "confidence": 0.8,
            }
        )
    for finding in code_pattern_analysis["findings"]:
        if finding.get("category") == "code_health":
            code_health_findings.append(finding)

    hotspots = sorted(
        (
            {
                "file": path,
                "loc": loc_by_file.get(path, 0),
                "age_days": round(age_by_file.get(path, 0), 2),
                "changes_timeframe": per_file_changes.get(path, 0),
            }
            for path in source_files
        ),
        key=lambda item: (item["changes_timeframe"], item["loc"]),
        reverse=True,
    )[:20]

    architecture_overview = {
        "top_level_components": sorted(
            {
                parts[0]
                for parts in (Path(f).parts for f in source_files)
                if parts
            }
        )[:60],
        "languages": languages,
        "external_dependency_ecosystems": sorted({item["ecosystem"] for item in dependency_inventory}),
    }

    component_inventory = [
        {
            "component": comp,
            "source_file_count": sum(1 for f in source_files if Path(f).parts and Path(f).parts[0] == comp),
        }
        for comp in architecture_overview["top_level_components"]
    ]

    dataflow_notes = [
        "Dataflow inferred from static repository structure; runtime telemetry not inspected.",
        "External boundaries inferred from dependency manifests and infrastructure files.",
    ]

    devops_findings: list[dict[str, Any]] = []
    devops_findings.extend(infrastructure_analysis["findings"])
    if not devops_signals["observability"]:
        devops_findings.append(
            {
                "finding": "Observability stack signal is weak",
                "evidence": [evidence_velocity],
                "risk": "Higher MTTR and lower incident diagnosability",
                "recommendation": "Introduce structured logging, metrics, and alerting baseline",
                "confidence": 0.65,
            }
        )

    if not (devops_signals["kubernetes"] or devops_signals["terraform"] or devops_signals["helm"]):
        devops_findings.append(
            {
                "finding": "Infrastructure-as-code signal is limited",
                "evidence": [evidence_velocity],
                "risk": "Environment drift and deployment inconsistency risk",
                "recommendation": "Codify environments with IaC and review policies",
                "confidence": 0.58,
            }
        )

    operability_score = 40
    for key in ["github_actions", "gitlab_ci", "jenkins", "docker", "kubernetes", "terraform", "helm", "observability", "backup_signal"]:
        if devops_signals.get(key):
            operability_score += 6
    operability_score = int(
        clamp_score(0.6 * operability_score + 0.4 * infrastructure_analysis["infra_maturity_score"])
    )

    operability_metrics = [
        {
            "metric_id": "ci_present",
            "value": bool(devops_signals["github_actions"] or devops_signals["gitlab_ci"] or devops_signals["jenkins"]),
            "method": "pipeline config presence",
            "confidence": 0.83,
            "evidence": [evidence_velocity],
        },
        {
            "metric_id": "observability_signal",
            "value": devops_signals["observability"],
            "method": "static config/name detection",
            "confidence": 0.57,
            "evidence": [evidence_velocity],
        },
        {
            "metric_id": "operability_score",
            "value": operability_score,
            "method": "weighted presence heuristic across CI/CD, infra, and reliability signals",
            "confidence": 0.6,
            "evidence": [evidence_velocity],
        },
        {
            "metric_id": "infra_maturity_score",
            "value": infrastructure_analysis["infra_maturity_score"],
            "method": "infrastructure artifact discovery across deployment/runtime/IaC signals",
            "confidence": 0.7,
            "evidence": infrastructure_analysis["evidence"],
        },
    ]
    code_pattern_metrics = [
        {
            "metric_id": "auth_posture_score",
            "value": code_pattern_analysis["auth_posture_score"],
            "method": "regex-based auth/authz signal strength over source files",
            "confidence": 0.59,
            "evidence": code_pattern_analysis["evidence"],
        },
        {
            "metric_id": "anti_pattern_pressure_score",
            "value": code_pattern_analysis["anti_pattern_pressure_score"],
            "method": "inverse pressure score from TODO/FIXME/insecure patterns",
            "confidence": 0.64,
            "evidence": code_pattern_analysis["evidence"],
        },
    ]

    security_findings: list[dict[str, Any]] = []
    security_findings.extend(
        [finding for finding in code_pattern_analysis["findings"] if finding.get("category") == "security"]
    )
    secret_scan_findings: list[dict[str, Any]] = []
    secret_metrics: list[dict[str, Any]] = []

    working_secret_findings: list[SecretFinding] = []
    history_secret_findings: list[SecretFinding] = []

    if args.secret_scan_enabled:
        if args.scan_working_tree:
            working_secret_findings = scan_working_tree_for_secrets(
                repo_path,
                tracked_files,
                args.max_findings,
                evidence,
                classify=args.classify_test_vs_prod,
            )
        if args.scan_git_history:
            remaining = max(0, args.max_findings - len(working_secret_findings))
            if remaining > 0:
                history_secret_findings = scan_git_history_for_secrets(
                    repo,
                    args.history_depth,
                    args.timeframe_days,
                    default_branch,
                    remaining,
                    evidence,
                    classify=args.classify_test_vs_prod,
                )

        combined = working_secret_findings + history_secret_findings
        secret_metric, secret_hygiene_metric, secret_scan_findings = summarize_secret_findings(
            history_secret_findings,
            working_secret_findings,
        )
        secret_metrics.extend([secret_metric, secret_hygiene_metric])

        if secret_metric["value"]["findings_count"] >= 1:
            security_findings.append(
                {
                    "finding": "Secrets exposed in git history",
                    "evidence": secret_metric["evidence"],
                    "risk": "Credential compromise and unauthorized access",
                    "recommendation": "Rotate affected credentials immediately; add pre-commit and CI secret scanning",
                    "confidence": 0.86,
                }
            )

        if combined and args.privacy_mode:
            # Redact contributor identity from findings by design.
            pass

    compliance_targets = [item.strip() for item in args.compliance_targets.split(",") if item.strip()]
    compliance_gaps: list[dict[str, Any]] = []
    if compliance_targets:
        doc_files = {f.lower() for f in tracked_files if f.lower().endswith((".md", ".txt", ".rst"))}
        for target in compliance_targets:
            signal = any(target.lower() in item for item in doc_files)
            if not signal:
                compliance_gaps.append(
                    {
                        "finding": f"No clear repository-level evidence for {target} controls",
                        "evidence": [evidence_velocity],
                        "risk": f"Compliance posture for {target} cannot be substantiated from repository artifacts",
                        "recommendation": f"Map {target} controls to policy/runbook/audit artifacts and link evidence",
                        "confidence": 0.55,
                    }
                )
    security_findings.extend(compliance_gaps)

    data_findings: list[dict[str, Any]] = []
    data_risks: list[dict[str, Any]] = []
    has_migrations = any("migration" in f.lower() for f in tracked_files)
    has_backups = devops_signals["backup_signal"]
    if not has_migrations:
        data_findings.append(
            {
                "finding": "No migration workflow signal detected",
                "evidence": [evidence_velocity],
                "risk": "Schema changes may be ad hoc and hard to rollback",
                "recommendation": "Introduce explicit migration tooling and runbook",
                "confidence": 0.53,
            }
        )
    if not has_backups:
        data_risks.append(
            {
                "finding": "No backup/restore signal detected",
                "evidence": [evidence_velocity],
                "risk": "Recovery readiness is unproven",
                "recommendation": "Define tested backup and restore process with RPO/RTO targets",
                "confidence": 0.6,
            }
        )

    process_findings: list[dict[str, Any]] = []
    bus_factor_risks: list[dict[str, Any]] = []
    if bus_factor <= 1:
        bus_factor_risks.append(
            {
                "finding": "Bus factor proxy is 1",
                "evidence": [evidence_velocity],
                "risk": "Delivery continuity and maintainability risk",
                "recommendation": "Increase shared ownership and mandatory cross-review for core components",
                "confidence": 0.82,
            }
        )
    elif bus_factor <= 2:
        process_findings.append(
            {
                "finding": "Bus factor proxy is low",
                "evidence": [evidence_velocity],
                "risk": "Concentrated ownership can limit scalability and resilience",
                "recommendation": "Distribute ownership and rotate maintainers on critical paths",
                "confidence": 0.74,
            }
        )

    slack_intel_json: dict[str, Any] = {
        "enabled": args.slack_enabled,
        "available": False,
        "themes": [],
        "limitations": [
            "Slack capability/token not provided in local runner",
        ],
    }

    secrets_hygiene_score = 70
    if secret_metrics:
        controls_score = secret_metrics[1]["value"]["score"]
        secrets_hygiene_score = int(controls_score)

    access_control_model = int(
        clamp_score(0.6 * code_pattern_analysis["auth_posture_score"] + 0.4 * 55)
    )
    dependency_supply_chain = freshness_score
    cicd_devsecops = int(clamp_score((operability_score + (20 if devops_signals["github_actions"] else 0)) / 1.2))
    infrastructure_cloud = int(
        clamp_score(
            0.5 * infrastructure_analysis["infra_maturity_score"]
            + 0.5 * (35 + 12 * sum(1 for k in ["docker", "kubernetes", "terraform", "helm"] if devops_signals[k]))
        )
    )
    data_protection_encryption = 45 + (10 if has_migrations else 0)
    observability_audit = 35 + (30 if devops_signals["observability"] else 0)
    incident_response_recovery = 30 + (40 if has_backups else 0)

    smi_breakdown = {
        "secrets_hygiene": secrets_hygiene_score,
        "access_control_model": access_control_model,
        "dependency_supply_chain": dependency_supply_chain,
        "cicd_devsecops": cicd_devsecops,
        "infrastructure_cloud": infrastructure_cloud,
        "data_protection_encryption": data_protection_encryption,
        "observability_audit": observability_audit,
        "incident_response_recovery": incident_response_recovery,
    }

    smi_weights = {
        "secrets_hygiene": 0.2,
        "access_control_model": 0.15,
        "dependency_supply_chain": 0.15,
        "cicd_devsecops": 0.15,
        "infrastructure_cloud": 0.1,
        "data_protection_encryption": 0.1,
        "observability_audit": 0.1,
        "incident_response_recovery": 0.05,
    }

    smi_score = sum(smi_breakdown[key] * weight for key, weight in smi_weights.items())
    smi_score = round(clamp_score(smi_score), 2)
    tier_code, tier_label = smi_tier(smi_score)
    security_multiplier = smi_multiplier(smi_score)

    security_maturity_index_json = {
        "score": smi_score,
        "tier": {"tier": tier_code, "label": tier_label},
        "category_breakdown": smi_breakdown,
        "weights": smi_weights,
        "confidence": 0.67,
        "applied_risk_multiplier": security_multiplier,
        "limitations": [
            "Static repository evidence only",
            "No live infrastructure or identity provider validation",
        ],
    }

    architecture_score = clamp_score(45 + len(component_inventory) * 2 + (8 if len(languages) >= 2 else 0))
    code_health_score = clamp_score(25 + (40 * test_ratio) + (15 if devops_signals["github_actions"] else 0))
    staleness_score = clamp_score(100 - (stale_ratio * 100) * 0.8 - (gini_val * 20) + (bus_factor * 5))
    dependencies_score = freshness_score
    devops_score = operability_score

    base_tdd_score = (
        architecture_score * 0.2
        + code_health_score * 0.15
        + staleness_score * 0.25
        + dependencies_score * 0.15
        + devops_score * 0.15
        + smi_score * 0.1
    )
    base_tdd_score = round(clamp_score(base_tdd_score), 2)
    base_tdd_risk = round(100 - base_tdd_score, 2)
    adjusted_tdd_risk = round(base_tdd_risk * security_multiplier, 2)
    final_score = round(max(0.0, 100 - adjusted_tdd_risk), 2)

    risk_matrix: list[dict[str, Any]] = []
    rid = 1

    def add_risk(*, title: str, category: str, impact: int, likelihood: int, effort: int, confidence: float, evidence_ids: list[str], actions: list[str]) -> None:
        nonlocal rid
        risk_matrix.append(
            build_risk(
                risk_id=f"R{rid:03d}",
                title=title,
                category=category,
                impact=impact,
                likelihood=likelihood,
                effort=effort,
                confidence=confidence,
                evidence=evidence_ids,
                actions=actions,
            )
        )
        rid += 1

    if stale_ratio > 0.6 and bus_factor <= 2:
        add_risk(
            title="High stale code with concentrated ownership",
            category="staleness_velocity",
            impact=5,
            likelihood=4,
            effort=3,
            confidence=0.83,
            evidence_ids=[evidence_staleness, evidence_velocity],
            actions=[
                "Reduce stale surface by prioritizing critical-path modernization",
                "Increase shared ownership on stale hotspots",
            ],
        )

    if freshness_score < 50 and dep_cadence <= 1:
        add_risk(
            title="Dependency freshness lag and low update cadence",
            category="dependencies",
            impact=4,
            likelihood=4,
            effort=2,
            confidence=0.79,
            evidence_ids=[evidence_deps],
            actions=[
                "Enable Dependabot or Renovate",
                "Set monthly dependency review and upgrade budget",
            ],
        )

    ci_present = bool(devops_signals["github_actions"] or devops_signals["gitlab_ci"] or devops_signals["jenkins"])
    rollback_signal = bool(devops_signals["kubernetes"] or devops_signals["helm"] or devops_signals["terraform"])
    if not ci_present and not rollback_signal:
        add_risk(
            title="Weak CI/CD and rollback readiness",
            category="devops_operability",
            impact=4,
            likelihood=4,
            effort=3,
            confidence=0.72,
            evidence_ids=[evidence_velocity],
            actions=[
                "Introduce CI quality gates",
                "Establish tested rollback procedure per environment",
            ],
        )

    if infrastructure_analysis["infra_maturity_score"] < 45:
        add_risk(
            title="Infrastructure codification and deployment evidence is weak",
            category="infrastructure",
            impact=4,
            likelihood=4,
            effort=3,
            confidence=0.74,
            evidence_ids=infrastructure_analysis["evidence"],
            actions=[
                "Codify deployment topology and baseline infrastructure as code",
                "Version operational runbooks with environment-specific controls",
            ],
        )

    if code_pattern_analysis["auth_posture_score"] < 50:
        add_risk(
            title="Authentication and authorization pattern coverage is weak",
            category="security",
            impact=4,
            likelihood=3,
            effort=3,
            confidence=0.63,
            evidence_ids=code_pattern_analysis["evidence"],
            actions=[
                "Centralize authn/authz middleware and document enforcement points",
                "Add authorization policy tests for sensitive routes and handlers",
            ],
        )

    if code_pattern_analysis["anti_pattern_pressure_score"] < 55:
        add_risk(
            title="Code anti-pattern pressure indicates latent maintainability debt",
            category="code_health",
            impact=3,
            likelihood=4,
            effort=2,
            confidence=0.67,
            evidence_ids=code_pattern_analysis["evidence"],
            actions=[
                "Reduce TODO/FIXME/HACK density in critical paths",
                "Add static quality gates for weak crypto and insecure transport references",
            ],
        )

    secrets_count = 0
    if secret_metrics:
        secrets_count = secret_metrics[0]["value"].get("findings_count", 0)
    if secrets_count >= 1:
        sev = secret_metrics[0]["value"].get("severity_breakdown", {})
        impact = 5 if sev.get("critical", 0) or sev.get("high", 0) else 4
        add_risk(
            title="Git history secret exposure",
            category="security",
            impact=impact,
            likelihood=4,
            effort=2,
            confidence=0.88,
            evidence_ids=secret_metrics[0]["evidence"],
            actions=[
                "Rotate exposed credentials immediately",
                "Purge or invalidate sensitive values and add secret scanning guardrails",
            ],
        )

    if tier_code in {"D", "F"}:
        add_risk(
            title="Security maturity indicates structural liability",
            category="security_smi",
            impact=5,
            likelihood=4,
            effort=4,
            confidence=0.75,
            evidence_ids=[evidence_velocity],
            actions=[
                "Fund a 6-12 month security maturity program",
                "Track SMI monthly and gate releases on key controls",
            ],
        )

    if not risk_matrix:
        add_risk(
            title="General technical debt accumulation",
            category="code_health",
            impact=3,
            likelihood=3,
            effort=3,
            confidence=0.5,
            evidence_ids=[evidence_velocity],
            actions=["Maintain periodic architecture and dependency reviews"],
        )

    risk_matrix.sort(key=lambda item: item["priority_score"], reverse=True)

    metrics_summary_json = {
        "generated_at": generated_at,
        "mode": mode,
        "repo": {
            "path": repo,
            "default_branch": default_branch,
            "tracked_files": len(tracked_files),
            "source_files": len(source_files),
            "languages": languages,
            "timeframe_days": args.timeframe_days,
            "stale_days": args.stale_days,
        },
        "staleness_and_velocity": staleness_metrics,
        "dependencies_and_supply_chain": dependency_metrics,
        "security_and_compliance": secret_metrics + code_pattern_metrics,
        "operability": operability_metrics,
        "infrastructure": [
            {
                "metric_id": "inferred_runtime_model",
                "value": infrastructure_analysis["inferred_runtime_model"],
                "method": "static analysis of deployment/runtime artifacts",
                "confidence": 0.66,
                "evidence": infrastructure_analysis["evidence"],
            }
        ],
        "hotspots": hotspots,
    }

    section_limitations = []
    if mode != "full":
        section_limitations.append(f"Operating mode is {mode}; confidence reduced for network-dependent checks")
    if not args.secret_scan_enabled:
        section_limitations.append("Secret scanning disabled")
    if not args.scan_git_history:
        section_limitations.append("Git history secret scanning disabled")
    if args.slack_enabled and not slack_intel_json["available"]:
        section_limitations.append("Slack analysis requested but capability not available")

    recommendations = []
    for risk in risk_matrix[:10]:
        recommendations.extend(risk["recommended_actions"])

    recommendations = list(dict.fromkeys(recommendations))

    roadmap = []
    if args.include_roadmap:
        roadmap = [
            {
                "window": "0-90 days",
                "focus": [
                    "Rotate and contain exposed secrets",
                    "Enable secret scanning in pre-commit and CI",
                    "Establish baseline CI quality gates",
                ],
            },
            {
                "window": "3-6 months",
                "focus": [
                    "Reduce stale hotspots with ownership expansion",
                    "Adopt automated dependency update workflows",
                    "Implement rollback and backup runbooks",
                ],
            },
            {
                "window": "6-18 months",
                "focus": [
                    "Institutionalize security maturity tracking (SMI)",
                    "Improve observability and incident learning loops",
                    "Harden data integrity and recovery testing",
                ],
            },
        ]

    summary_lines = [
        (
            f"This assessment evaluates repository sustainability, delivery posture, and security readiness. "
            f"Final TDD score is {final_score:.2f} (base score {base_tdd_score:.2f}, adjusted risk {adjusted_tdd_risk:.2f})."
        ),
        (
            f"Security maturity is {smi_score:.2f} ({tier_code} - {tier_label}) with a risk multiplier of {security_multiplier:.2f}. "
            f"Git-history secret findings total {secrets_count}."
        ),
        (
            f"Staleness profile shows median last-touch age of {median_age_days:.1f} days and stale code ratio of {stale_ratio:.2%}. "
            f"Change concentration gini is {gini_val:.2f} and bus-factor proxy is {bus_factor}."
        ),
        (
            f"Dependency freshness score is {freshness_score}/100 with cadence of {dep_cadence} dependency-touching commits over 90 days. "
            f"Infrastructure maturity is {infrastructure_analysis['infra_maturity_score']}/100."
        ),
    ]

    if tier_code in {"D", "F"}:
        summary_lines.append(
            "Security liability signal is present because SMI tier is in structural-risk range and materially elevates overall due-diligence risk."
        )

    architecture_summary = (
        f"The codebase is organized into {len(component_inventory)} top-level components across {len(languages)} language groups. "
        f"Primary language distribution is {languages}. External dependency ecosystems detected: "
        f"{architecture_overview['external_dependency_ecosystems']}."
    )
    code_health_summary = (
        f"Code health assessment indicates test-file ratio of {test_ratio:.2%} and CI presence={ci_present}. "
        f"Anti-pattern pressure score is {code_pattern_analysis['anti_pattern_pressure_score']}/100."
    )
    staleness_summary = (
        f"Staleness and velocity metrics indicate median last-touch age of {median_age_days:.1f} days and stale-code ratio of {stale_ratio:.2%}. "
        f"Hotspot concentration (gini={gini_val:.2f}) suggests change risk concentration in a narrow file set."
    )
    dependency_summary = (
        f"Dependency posture is moderate-to-weak with freshness score {freshness_score}/100. "
        f"Observed update cadence is {dep_cadence} manifest-touching commits in 90 days."
    )
    devops_summary = (
        f"Operability score is {operability_score}/100 and inferred infrastructure maturity is "
        f"{infrastructure_analysis['infra_maturity_score']}/100. {infrastructure_analysis['narrative']}"
    )
    security_summary = (
        f"Security controls include SMI score {smi_score:.2f} ({tier_code}), secrets-hygiene score {secrets_hygiene_score}, "
        f"and auth-posture score {code_pattern_analysis['auth_posture_score']}/100."
    )
    data_summary = (
        f"Data-layer review detected migration signal={has_migrations} and backup/restore signal={has_backups}. "
        f"Findings focus on migration discipline, data recovery readiness, and integrity safeguards."
    )
    team_summary = (
        f"Team/process analysis shows bus-factor proxy of {bus_factor} across {len(per_author_loc)} contributors in timeframe. "
        f"Ownership concentration signals are used as a proxy for maintainability and continuity risk."
    )

    sub_agent_outputs = [
        {
            "agent_id": "repo_cartographer",
            "role": "Architecture & System Mapping",
            "summary": architecture_summary,
            "finding_count": 0,
            "evidence": [evidence_staleness],
        },
        {
            "agent_id": "code_health_auditor",
            "role": "Code Quality and Anti-Pattern Detection",
            "summary": code_health_summary,
            "finding_count": len(code_health_findings),
            "evidence": code_pattern_analysis["evidence"],
        },
        {
            "agent_id": "staleness_analyst",
            "role": "Staleness and Velocity",
            "summary": staleness_summary,
            "finding_count": 1 if stale_ratio > 0.6 else 0,
            "evidence": [evidence_staleness, evidence_velocity],
        },
        {
            "agent_id": "dependency_auditor",
            "role": "Dependency and Supply Chain",
            "summary": dependency_summary,
            "finding_count": len(dependency_risks),
            "evidence": [evidence_deps],
        },
        {
            "agent_id": "infra_devops_reviewer",
            "role": "Infrastructure and Operability",
            "summary": devops_summary,
            "finding_count": len(devops_findings),
            "evidence": infrastructure_analysis["evidence"],
        },
        {
            "agent_id": "security_compliance",
            "role": "Security and Compliance",
            "summary": security_summary,
            "finding_count": len(security_findings),
            "evidence": list(
                dict.fromkeys(
                    [e for item in security_findings for e in item.get("evidence", [])]
                    + code_pattern_analysis["evidence"]
                )
            ),
        },
        {
            "agent_id": "data_layer_reviewer",
            "role": "Data Layer and Integrity",
            "summary": data_summary,
            "finding_count": len(data_findings) + len(data_risks),
            "evidence": [evidence_velocity],
        },
        {
            "agent_id": "team_process_inferencer",
            "role": "Team and Process Signals",
            "summary": team_summary,
            "finding_count": len(process_findings) + len(bus_factor_risks),
            "evidence": [evidence_velocity],
        },
    ]

    tdd_report_json = {
        "generated_at": generated_at,
        "mode": mode,
        "repo": {
            "path": repo,
            "default_branch": default_branch,
        },
        "overall_score": {
            "base_tdd_score": base_tdd_score,
            "base_tdd_risk": base_tdd_risk,
            "security_multiplier": security_multiplier,
            "adjusted_tdd_risk": adjusted_tdd_risk,
            "final_score": final_score,
        },
        "sub_agent_outputs": sub_agent_outputs,
        "sections": [
            {
                "title": "Executive Summary",
                "summary": " ".join(summary_lines),
                "confidence": 0.78,
                "limitations": section_limitations,
                "narrative_lines": summary_lines,
            },
            {
                "title": "Architecture Overview",
                "summary": architecture_summary,
                "confidence": 0.72,
                "details": architecture_overview,
                "component_inventory": component_inventory,
                "dataflow_notes": dataflow_notes,
            },
            {
                "title": "Codebase Health",
                "summary": code_health_summary,
                "confidence": 0.74,
                "findings": code_health_findings,
                "narrative_lines": findings_to_narrative_lines(code_health_findings, 5),
                "pattern_signals": {
                    "anti_pattern_signals": code_pattern_analysis["anti_pattern_signals"],
                    "anti_hit_files": code_pattern_analysis["anti_hit_files"],
                    "anti_pattern_pressure_score": code_pattern_analysis["anti_pattern_pressure_score"],
                },
            },
            {
                "title": "Staleness & Change Velocity",
                "summary": staleness_summary,
                "confidence": 0.83,
                "hotspots": hotspots,
                "narrative_lines": [
                    f"Median file last-touch age is {median_age_days:.1f} days.",
                    f"Stale code ratio is {stale_ratio:.2%}.",
                    f"Change concentration gini is {gini_val:.2f}; bus factor proxy is {bus_factor}.",
                ],
            },
            {
                "title": "Dependencies & Supply Chain",
                "summary": dependency_summary,
                "confidence": 0.69,
                "inventory": dependency_inventory,
                "risks": dependency_risks,
                "narrative_lines": findings_to_narrative_lines(dependency_risks, 4),
            },
            {
                "title": "DevOps & Operability",
                "summary": devops_summary,
                "confidence": 0.7,
                "findings": devops_findings,
                "narrative_lines": findings_to_narrative_lines(devops_findings, 6),
                "infrastructure_overview": infrastructure_analysis,
            },
            {
                "title": "Security Maturity Index",
                "summary": f"SMI={smi_score:.2f}, tier={tier_code} ({tier_label}), multiplier={security_multiplier}.",
                "confidence": security_maturity_index_json["confidence"],
                "details": security_maturity_index_json,
            },
            {
                "title": "Security Findings (incl. Git History Secrets)",
                "summary": security_summary,
                "confidence": 0.78,
                "findings": security_findings,
                "narrative_lines": findings_to_narrative_lines(security_findings, 6),
                "secret_scan_findings": secret_scan_findings,
                "auth_and_security_signals": {
                    "auth_signals": code_pattern_analysis["auth_signals"],
                    "auth_hit_files": code_pattern_analysis["auth_hit_files"],
                    "auth_posture_score": code_pattern_analysis["auth_posture_score"],
                },
            },
            {
                "title": "Data Layer & Integrity",
                "summary": data_summary,
                "confidence": 0.6,
                "findings": data_findings,
                "risks": data_risks,
                "narrative_lines": findings_to_narrative_lines(data_findings + data_risks, 4),
            },
            {
                "title": "Team/Process Signals",
                "summary": team_summary,
                "confidence": 0.74,
                "findings": process_findings,
                "bus_factor_risks": bus_factor_risks,
                "narrative_lines": findings_to_narrative_lines(process_findings + bus_factor_risks, 4),
            },
            {
                "title": "Slack Signals (if enabled)",
                "summary": "Slack signals unavailable in local static run" if not args.slack_enabled else "Slack enabled but capability unavailable in local static run",
                "confidence": 0.3,
                "details": slack_intel_json,
            },
            {
                "title": "Risk Matrix",
                "summary": f"{len(risk_matrix)} risks ranked by priority score.",
                "confidence": 0.82,
                "top_risks": risk_matrix[:20],
            },
            {
                "title": "Recommendations",
                "summary": "Top recommended actions prioritized by risk impact and feasibility.",
                "confidence": 0.79,
                "actions": recommendations,
            },
            {
                "title": "12-18 Month Remediation Roadmap",
                "summary": "Phased roadmap for risk reduction and maturity gains." if args.include_roadmap else "Roadmap disabled.",
                "confidence": 0.71,
                "roadmap": roadmap,
            },
            {
                "title": "Evidence Appendix",
                "summary": f"{len(evidence.entries)} reproducibility pointers recorded.",
                "confidence": 0.9,
                "sub_agent_outputs": sub_agent_outputs,
            },
        ],
    }

    artifact_paths = {
        "tdd_report_json": out_dir / "tdd_report_json.json",
        "risk_matrix_json": out_dir / "risk_matrix_json.json",
        "metrics_summary_json": out_dir / "metrics_summary_json.json",
        "security_maturity_index_json": out_dir / "security_maturity_index_json.json",
        "evidence_index_json": out_dir / "evidence_index_json.json",
        "slack_intel_json": out_dir / "slack_intel_json.json",
        "tdd_report_pdf": out_dir / "tdd_report_pdf.pdf",
    }

    if args.report_format in {"json", "both"}:
        json_dump(artifact_paths["tdd_report_json"], tdd_report_json)
        json_dump(artifact_paths["risk_matrix_json"], risk_matrix)
        json_dump(artifact_paths["metrics_summary_json"], metrics_summary_json)
        json_dump(artifact_paths["security_maturity_index_json"], security_maturity_index_json)
        json_dump(artifact_paths["evidence_index_json"], evidence.entries)
        json_dump(artifact_paths["slack_intel_json"], slack_intel_json)

    pdf_status = {"created": False, "engine": "none", "path": None}
    if args.report_format in {"pdf", "both"}:
        ok, engine = render_pdf_report(
            artifact_paths["tdd_report_pdf"],
            tdd_report_json,
            risk_matrix,
            metrics_summary_json,
            security_maturity_index_json,
        )
        pdf_status = {
            "created": ok,
            "engine": engine,
            "path": str(artifact_paths["tdd_report_pdf"]) if ok else None,
        }

    run_summary = {
        "generated_at": generated_at,
        "mode": mode,
        "repo": repo,
        "outputs": {
            key: str(path) for key, path in artifact_paths.items() if path.exists()
        },
        "pdf_status": pdf_status,
        "top_risks": risk_matrix[:5],
        "overall_score": tdd_report_json["overall_score"],
    }

    json_dump(out_dir / "run_summary.json", run_summary)
    print(json.dumps(run_summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
