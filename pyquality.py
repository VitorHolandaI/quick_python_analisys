#!/usr/bin/env python3
"""
PyQuality — Aggregated Python Code Quality CLI
================================================
Orchestrates industry-standard tools and unifies their output
into a single quality report with an overall grade.

Tools used:
  • pylint     — Linting, code smells, conventions, refactoring hints
  • flake8     — PEP 8 style + pyflakes logical errors
  • bandit     — Security vulnerability scanning
  • radon      — Cyclomatic complexity & maintainability index
  • vulture    — Dead code detection
  • mypy       — Static type checking

Usage:
    python pyquality.py <path>                # Analyze file or directory
    python pyquality.py <path> -v             # Verbose (show all issues)
    python pyquality.py <path> --json         # JSON output
    python pyquality.py <path> -t B           # Fail if grade < B

Requirements:
    pip install pylint flake8 bandit radon vulture mypy
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from html import escape as html_escape
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


# ═══════════════════════════════════════════════════════════════════════════════
# ANSI COLORS
# ═══════════════════════════════════════════════════════════════════════════════

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BG_RED = "\033[41m"

NO_COLOR = os.environ.get("NO_COLOR") is not None


def c(code: str, text: str) -> str:
    if NO_COLOR:
        return text
    return f"{code}{text}{RESET}"


# ═══════════════════════════════════════════════════════════════════════════════
# DATA TYPES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Issue:
    tool: str
    file: str
    line: int
    col: int
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW, INFO
    code: str           # e.g. W0611, E302, B101
    message: str
    category: str       # Bug, Security, Style, Convention, Complexity, Dead Code, Type Error

    @property
    def severity_weight(self) -> int:
        return {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 3, "LOW": 1, "INFO": 0}.get(self.severity, 0)


@dataclass
class Report:
    path: str
    analyzed_files: List[str] = field(default_factory=list)
    files_analyzed: int = 0
    total_lines: int = 0
    code_lines: int = 0
    comment_lines: int = 0
    blank_lines: int = 0
    issues: List[Issue] = field(default_factory=list)
    pylint_score: Optional[float] = None
    avg_complexity: float = 0.0
    max_complexity: float = 0.0
    max_complexity_func: str = ""
    maintainability_index: float = 100.0
    dead_code_count: int = 0
    type_errors: int = 0
    security_issues: int = 0
    quality_score: float = 100.0
    grade: str = "A"
    tool_errors: Dict[str, str] = field(default_factory=dict)
    tool_outputs: List[dict] = field(default_factory=list)
    radon_details: List[dict] = field(default_factory=list)
    tool_scores: Dict[str, dict] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# FILE DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

SKIP_DIRS = {
    "venv", ".venv", "env", ".env", "node_modules", "__pycache__",
    ".git", ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
    "dist", "build", ".eggs", "egg-info",
}

COMMAND_LOG: List[dict] = []
PROJECT_ROOT = Path(__file__).resolve().parent
SKIP_PROJECT_FILES = {
    PROJECT_ROOT / "pyquality.py",
}

TOOL_DETAILS = [
    (
        "pylint",
        "Linting & code smells",
        "Finds bugs, questionable patterns, naming problems, and maintainability issues.",
    ),
    (
        "flake8",
        "PEP 8 style checks",
        "Checks formatting, unused imports, syntax-adjacent bugs, and pyflakes errors.",
    ),
    (
        "bandit",
        "Security scanning",
        "Looks for risky Python patterns such as unsafe subprocess, debug servers, and weak crypto.",
    ),
    (
        "radon",
        "Complexity & maintainability",
        "Measures cyclomatic complexity, raw line metrics, and maintainability index.",
    ),
    (
        "vulture",
        "Dead code detection",
        "Reports likely unused functions, variables, imports, classes, and unreachable code.",
    ),
    (
        "mypy",
        "Type checking",
        "Uses type hints to catch incompatible values, missing attributes, and bad call signatures.",
    ),
]


def find_python_files(path: str) -> List[str]:
    p = Path(path)
    if p.is_file() and p.suffix == ".py":
        return [str(p)]
    files: List[str] = []
    if p.is_dir():
        for f in sorted(p.rglob("*.py")):
            if any(d in f.parts for d in SKIP_DIRS):
                continue
            if f.resolve() in SKIP_PROJECT_FILES:
                continue
            files.append(str(f))
    return files


def resolve_tool_path(tool_name: str) -> str:
    resolved = shutil.which(tool_name)
    if resolved:
        return resolved

    bin_dirs = [Path(sys.executable).resolve().parent]
    project_root = Path(__file__).resolve().parent
    venv_dir_name = "Scripts" if os.name == "nt" else "bin"
    bin_dirs.append(project_root / ".venv" / venv_dir_name)

    for bin_dir in bin_dirs:
        candidate = bin_dir / tool_name
        if candidate.exists():
            return str(candidate)
        if os.name == "nt":
            exe_candidate = candidate.with_suffix(".exe")
            if exe_candidate.exists():
                return str(exe_candidate)

    return tool_name


def default_issue_file(files: Sequence[str]) -> str:
    return files[0] if files else ""


def as_str(value: object, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL RUNNERS
# ═══════════════════════════════════════════════════════════════════════════════

def max_parallel_jobs() -> int:
    override = os.environ.get("PYQUALITY_MAX_JOBS")
    if override:
        try:
            return max(1, int(override))
        except ValueError:
            pass

    cpu_count = os.cpu_count() or 1
    return max(1, cpu_count // 3)


def run_cmd(cmd: List[str], timeout: int = 120) -> Tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        COMMAND_LOG.append({
            "cmd": cmd,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        })
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        stderr = f"Tool not found: {cmd[0]}"
        COMMAND_LOG.append({
            "cmd": cmd,
            "stdout": "",
            "stderr": stderr,
            "returncode": -1,
        })
        return "", stderr, -1
    except subprocess.TimeoutExpired:
        stderr = f"Timeout after {timeout}s"
        COMMAND_LOG.append({
            "cmd": cmd,
            "stdout": "",
            "stderr": stderr,
            "returncode": -1,
        })
        return "", stderr, -1


# ── PYLINT ──────────────────────────────────────────────────────────────────

def run_pylint(files: List[str]) -> Tuple[List[Issue], Optional[float], Optional[str]]:
    cmd = [
        resolve_tool_path("pylint"),
        "--output-format=json2",
        "--disable=C0114,C0115,C0116",
        "--max-line-length=120",
        f"--jobs={max_parallel_jobs()}",
        *files,
    ]
    stdout, stderr, rc = run_cmd(cmd)
    issues: List[Issue] = []
    score = None

    if rc == -1:
        return issues, score, stderr or "Failed to run pylint"

    for line in stderr.splitlines():
        m = re.search(r"rated at (-?[\d.]+)/10", line)
        if m:
            score = float(m.group(1))

    if not stdout.strip():
        return issues, score, None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return issues, score, "Failed to parse pylint output"

    if isinstance(data, dict):
        stats = data.get("statistics", {})
        json_score = stats.get("score")
        if isinstance(json_score, (int, float)):
            score = float(json_score)

    severity_map = {
        "fatal": "CRITICAL", "error": "HIGH", "warning": "MEDIUM",
        "convention": "LOW", "refactor": "LOW", "information": "INFO",
    }
    category_map = {
        "fatal": "Bug", "error": "Bug", "warning": "Bug",
        "convention": "Convention", "refactor": "Code Smell",
        "information": "Info",
    }

    messages = data.get("messages", data) if isinstance(data, dict) else data
    for msg in messages:
        if isinstance(msg, dict):
            msg_type = msg.get("type", "warning")
            message_id = msg.get("message-id") or msg.get("messageId") or "?"
            issues.append(Issue(
                tool="pylint",
                file=as_str(msg.get("path"), default_issue_file(files)),
                line=int(msg.get("line", 0) or 0),
                col=int(msg.get("column", 0) or 0),
                severity=severity_map.get(msg_type, "MEDIUM"),
                code=as_str(message_id, "?"),
                message=as_str(msg.get("message")),
                category=category_map.get(msg_type, "Bug"),
            ))

    return issues, score, None


# ── FLAKE8 ──────────────────────────────────────────────────────────────────

def run_flake8(files: List[str]) -> Tuple[List[Issue], Optional[str]]:
    cmd = [
        resolve_tool_path("flake8"),
        "--max-line-length=120",
        "--format=%(path)s:%(row)d:%(col)d:%(code)s:%(text)s",
        *files,
    ]
    stdout, stderr, rc = run_cmd(cmd)
    issues: List[Issue] = []

    if rc == -1:
        return issues, stderr or "Failed to run flake8"

    for line in stdout.splitlines():
        m = re.match(r"^(.+?):(\d+):(\d+):([A-Z]\d+):(.+)$", line)
        if m:
            fpath, lineno, col, code, message = m.groups()
            if code.startswith("E9") or code.startswith("F"):
                severity, category = "HIGH", "Bug"
            elif code.startswith(("E", "W")):
                severity, category = "LOW", "Style"
            elif code.startswith("C9"):
                severity, category = "MEDIUM", "Complexity"
            else:
                severity, category = "LOW", "Style"

            issues.append(Issue(
                tool="flake8", file=fpath, line=int(lineno),
                col=int(col), severity=severity, code=code,
                message=message.strip(), category=category,
            ))

    return issues, None


# ── BANDIT ──────────────────────────────────────────────────────────────────

def run_bandit(files: List[str]) -> Tuple[List[Issue], Optional[str]]:
    cmd = [resolve_tool_path("bandit"), "-f", "json", "-q", *files]
    stdout, stderr, rc = run_cmd(cmd)
    issues: List[Issue] = []

    if rc == -1:
        return issues, stderr or "Failed to run bandit"

    if not stdout.strip():
        return issues, None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return issues, "Failed to parse bandit output"

    severity_map = {"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "MEDIUM"}
    for result in data.get("results", []):
        sev = result.get("issue_severity", "MEDIUM")
        issues.append(Issue(
            tool="bandit",
            file=result.get("filename", ""),
            line=result.get("line_number", 0),
            col=0,
            severity=severity_map.get(sev, "MEDIUM"),
            code=result.get("test_id", "?"),
            message=f"{result.get('issue_text', '')} (confidence: {result.get('issue_confidence', '?')})",
            category="Security",
        ))

    return issues, None


# ── RADON ───────────────────────────────────────────────────────────────────

def run_radon_cc(files: List[str]) -> Tuple[List[Issue], List[dict], Optional[str]]:
    cmd = [resolve_tool_path("radon"), "cc", "-s", "-j", *files]
    stdout, stderr, rc = run_cmd(cmd)
    issues: List[Issue] = []
    details: List[dict] = []

    if rc == -1:
        return issues, details, stderr or "Failed to run radon cc"

    if not stdout.strip():
        return issues, details, None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return issues, details, "Failed to parse radon cc output"

    for fpath, blocks in data.items():
        for block in blocks:
            cc = block.get("complexity", 0)
            name = block.get("name", "?")
            rank = block.get("rank", "?")
            lineno = block.get("lineno", 0)
            details.append({
                "file": fpath, "name": name, "type": block.get("type", "?"),
                "complexity": cc, "rank": rank, "line": lineno,
            })
            if cc > 15:
                issues.append(Issue(
                    tool="radon", file=fpath, line=lineno, col=0,
                    severity="HIGH", code=f"CC-{rank}",
                    message=f"'{name}' has cyclomatic complexity of {cc} (rank {rank})",
                    category="Complexity",
                ))
            elif cc > 10:
                issues.append(Issue(
                    tool="radon", file=fpath, line=lineno, col=0,
                    severity="MEDIUM", code=f"CC-{rank}",
                    message=f"'{name}' has cyclomatic complexity of {cc} (rank {rank})",
                    category="Complexity",
                ))

    return issues, details, None


def run_radon_mi(files: List[str]) -> Tuple[float, Optional[str]]:
    cmd = [resolve_tool_path("radon"), "mi", "-s", "-j", *files]
    stdout, stderr, rc = run_cmd(cmd)

    if rc == -1:
        return 100.0, stderr or "Failed to run radon mi"

    if not stdout.strip():
        return 100.0, None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return 100.0, "Failed to parse radon mi output"

    mi_values = []
    for fpath, info in data.items():
        if isinstance(info, dict):
            mi_values.append(info.get("mi", 100.0))
        elif isinstance(info, (int, float)):
            mi_values.append(float(info))

    if mi_values:
        return round(sum(mi_values) / len(mi_values), 1), None
    return 100.0, None


def run_radon_raw(files: List[str]) -> Tuple[Dict[str, int], Optional[str]]:
    cmd = [resolve_tool_path("radon"), "raw", "-s", "-j", *files]
    stdout, stderr, rc = run_cmd(cmd)
    totals = {"loc": 0, "sloc": 0, "comments": 0, "blank": 0, "multi": 0}

    if rc == -1:
        return totals, stderr or "Failed to run radon raw"

    if not stdout.strip():
        return totals, None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return totals, "Failed to parse radon raw output"

    for fpath, info in data.items():
        if isinstance(info, dict):
            totals["loc"] += info.get("loc", 0)
            totals["sloc"] += info.get("sloc", 0)
            totals["comments"] += info.get("comments", 0)
            totals["blank"] += info.get("blank", 0)
            totals["multi"] += info.get("multi", 0)

    return totals, None


# ── VULTURE ─────────────────────────────────────────────────────────────────

def run_vulture(files: List[str]) -> Tuple[List[Issue], Optional[str]]:
    cmd = [resolve_tool_path("vulture"), "--min-confidence=80", *files]
    stdout, stderr, rc = run_cmd(cmd)
    issues: List[Issue] = []

    if rc == -1:
        return issues, stderr or "Failed to run vulture"

    for line in stdout.splitlines():
        m = re.match(r"^(.+?):(\d+): (.+?)(\((\d+)% confidence\))?$", line.strip())
        if m:
            fpath = m.group(1)
            lineno = int(m.group(2))
            message = m.group(3).strip()
            confidence = int(m.group(5)) if m.group(5) else 80
            severity = "MEDIUM" if confidence >= 90 else "LOW"

            issues.append(Issue(
                tool="vulture", file=fpath, line=lineno, col=0,
                severity=severity, code=f"V{confidence}",
                message=message, category="Dead Code",
            ))

    return issues, None


# ── MYPY ────────────────────────────────────────────────────────────────────

def run_mypy(files: List[str]) -> Tuple[List[Issue], Optional[str]]:
    cmd = [
        resolve_tool_path("mypy"),
        "--ignore-missing-imports",
        "--no-error-summary",
        "--show-column-numbers",
        "--no-color-output",
        *files,
    ]
    stdout, stderr, rc = run_cmd(cmd, timeout=180)
    issues: List[Issue] = []

    if rc == -1:
        return issues, stderr or "Failed to run mypy"

    for line in stdout.splitlines():
        m = re.match(r"^(.+?):(\d+):(\d+): (error|warning|note): (.+)$", line.strip())
        if m:
            fpath, lineno, col, level, message = m.groups()
            severity_map = {"error": "HIGH", "warning": "MEDIUM", "note": "INFO"}
            issues.append(Issue(
                tool="mypy", file=fpath, line=int(lineno), col=int(col),
                severity=severity_map.get(level, "MEDIUM"),
                code="mypy",
                message=message.strip(),
                category="Type Error",
            ))

    return issues, None


# ═══════════════════════════════════════════════════════════════════════════════
# SCORING & GRADING
# ═══════════════════════════════════════════════════════════════════════════════

def score_maintainability_index(mi: float) -> float:
    """
    Convert Radon's raw MI into a quality-score component.

    Radon already reports MI >= 20 as rank A, so using the raw MI directly as
    a 0-100 score over-penalizes normal modules. Keep the raw MI in the report,
    but grade this component in practical bands.
    """
    if mi >= 85:
        return 100
    if mi >= 65:
        return 90 + (mi - 65) * 0.5
    if mi >= 50:
        return 80 + (mi - 50) * (10 / 15)
    if mi >= 20:
        return 60 + (mi - 20) * (20 / 30)
    return max(0, mi * 3)


def clamp_score(value: float) -> float:
    return round(max(0.0, min(100.0, value)), 1)


def make_tool_score(
    score: Optional[float],
    source: str,
    *,
    raw_value: Optional[float] = None,
    raw_scale: Optional[str] = None,
    details: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    normalized_score = None if score is None else clamp_score(score)
    return {
        "score": normalized_score,
        "grade": grade_from_score(normalized_score) if normalized_score is not None else None,
        "source": source,
        "raw_value": raw_value,
        "raw_scale": raw_scale,
        "details": details or {},
    }


def count_issue_severities(issues: List[Issue]) -> Dict[str, int]:
    return dict(Counter(issue.severity for issue in issues))


def penalty_score(issues: List[Issue], penalties: Dict[str, int]) -> float:
    total_penalty = sum(penalties.get(issue.severity, 0) for issue in issues)
    return clamp_score(100 - total_penalty)


def score_complexity_metric(avg_complexity: float) -> float:
    if avg_complexity <= 5:
        return 100.0
    if avg_complexity <= 10:
        return 100 - (avg_complexity - 5) * 4
    if avg_complexity <= 20:
        return 80 - (avg_complexity - 10) * 4
    if avg_complexity <= 30:
        return 40 - (avg_complexity - 20) * 3
    return 0.0


def build_pylint_tool_score(issues: List[Issue], pylint_score: Optional[float]) -> Dict[str, object]:
    severities = count_issue_severities(issues)
    return make_tool_score(
        None if pylint_score is None else pylint_score * 10,
        "Score nativo do relatorio do pylint.",
        raw_value=pylint_score,
        raw_scale="/10",
        details={
            "findings": len(issues),
            "severity_counts": severities,
        },
    )


def build_penalty_tool_score(
    issues: List[Issue],
    penalties: Dict[str, int],
    source: str,
) -> Dict[str, object]:
    severities = count_issue_severities(issues)
    return make_tool_score(
        penalty_score(issues, penalties),
        source,
        details={
            "findings": len(issues),
            "severity_counts": severities,
        },
    )


def build_radon_tool_score(
    maintainability_index: Optional[float],
    avg_complexity: Optional[float],
    max_complexity: Optional[float],
    block_count: Optional[int],
) -> Dict[str, object]:
    mi_score = clamp_score(maintainability_index if maintainability_index is not None else 100.0)
    cc_score = clamp_score(score_complexity_metric(avg_complexity or 0.0))
    return make_tool_score(
        (mi_score + cc_score) / 2,
        "Media entre maintainability index e complexidade reportados pelo radon.",
        details={
            "maintainability_index": maintainability_index,
            "avg_complexity": avg_complexity,
            "max_complexity": max_complexity,
            "blocks_analyzed": block_count or 0,
            "mi_score": mi_score,
            "complexity_score": cc_score,
        },
    )


PENALTY_TOOL_CONFIGS = {
    "flake8": (
        {"HIGH": 12, "MEDIUM": 6, "LOW": 2, "INFO": 1},
        "Score derivado apenas das ocorrencias reportadas pelo flake8.",
    ),
    "bandit": (
        {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 8, "LOW": 3},
        "Score derivado apenas das vulnerabilidades reportadas pelo bandit.",
    ),
    "vulture": (
        {"MEDIUM": 8, "LOW": 4},
        "Score derivado apenas dos itens de codigo morto reportados pelo vulture.",
    ),
    "mypy": (
        {"HIGH": 20, "MEDIUM": 8, "LOW": 2},
        "Score derivado apenas dos erros e avisos reportados pelo mypy.",
    ),
}


def compute_tool_score_map(
    name: str,
    *,
    issues: Optional[List[Issue]] = None,
    pylint_score: Optional[float] = None,
    maintainability_index: Optional[float] = None,
    avg_complexity: Optional[float] = None,
    max_complexity: Optional[float] = None,
    block_count: Optional[int] = None,
) -> Dict[str, object]:
    issues = issues or []
    if name == "pylint":
        return build_pylint_tool_score(issues, pylint_score)

    if name == "radon":
        return build_radon_tool_score(
            maintainability_index,
            avg_complexity,
            max_complexity,
            block_count,
        )

    penalty_config = PENALTY_TOOL_CONFIGS.get(name)
    if penalty_config:
        penalties, source = penalty_config
        return build_penalty_tool_score(issues, penalties, source)

    return make_tool_score(None, "Ferramenta sem score configurado.")


def unavailable_tool_score(error_message: str) -> Dict[str, object]:
    return make_tool_score(
        None,
        error_message,
        details={"error": error_message},
    )


def compute_quality_score(report: Report) -> float:
    """Average the per-tool scores generated from each tool's own report."""
    scores = [
        info["score"]
        for info in report.tool_scores.values()
        if info.get("score") is not None
    ]
    if not scores:
        return 0.0
    return round(sum(scores) / len(scores), 1)


def grade_from_score(score: float) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 65: return "C"
    if score >= 50: return "D"
    return "F"


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def analyze(path: str, skip_mypy: bool = False, show_progress: bool = True) -> Report:
    COMMAND_LOG.clear()
    report = Report(path=path)
    py_files = find_python_files(path)
    report.analyzed_files = list(py_files)
    report.files_analyzed = len(py_files)

    if not py_files:
        print(c(RED, f"Error: No Python files found in '{path}'"))
        sys.exit(1)

    if show_progress:
        print(c(DIM, f"  Scanning {report.files_analyzed} file(s)...\n"))

    # Run all tools
    steps = [(name, summary.lower()) for name, summary, _ in TOOL_DETAILS]

    for i, (name, desc) in enumerate(steps, 1):
        if name == "mypy" and skip_mypy:
            report.tool_scores[name] = make_tool_score(
                None,
                "Ferramenta pulada por --skip-mypy.",
                details={"skipped": True},
            )
            if show_progress:
                print(c(DIM, f"  [{i}/{len(steps)}] {name:<8} — skipped"))
            continue
        if show_progress:
            print(c(DIM, f"  [{i}/{len(steps)}] {name:<8} — {desc}..."))

        if name == "pylint":
            issues, score, err = run_pylint(py_files)
            report.issues.extend(issues)
            report.pylint_score = score
            if err:
                report.tool_scores[name] = unavailable_tool_score(err)
            else:
                report.tool_scores[name] = compute_tool_score_map(
                    name,
                    issues=issues,
                    pylint_score=score,
                )
            if err: report.tool_errors[name] = err

        elif name == "flake8":
            issues, err = run_flake8(py_files)
            report.issues.extend(issues)
            if err:
                report.tool_scores[name] = unavailable_tool_score(err)
            else:
                report.tool_scores[name] = compute_tool_score_map(name, issues=issues)
            if err: report.tool_errors[name] = err

        elif name == "bandit":
            issues, err = run_bandit(py_files)
            report.issues.extend(issues)
            report.security_issues = len(issues)
            if err:
                report.tool_scores[name] = unavailable_tool_score(err)
            else:
                report.tool_scores[name] = compute_tool_score_map(name, issues=issues)
            if err: report.tool_errors[name] = err

        elif name == "radon":
            cc_issues, cc_details, err = run_radon_cc(py_files)
            report.issues.extend(cc_issues)
            report.radon_details = cc_details
            if err: report.tool_errors["radon-cc"] = err

            mi, err = run_radon_mi(py_files)
            report.maintainability_index = mi
            if err: report.tool_errors["radon-mi"] = err

            raw, err = run_radon_raw(py_files)
            report.total_lines = raw["loc"]
            report.code_lines = raw["sloc"]
            report.comment_lines = raw["comments"] + raw["multi"]
            report.blank_lines = raw["blank"]
            if err: report.tool_errors["radon-raw"] = err

            if cc_details:
                ccs = [d["complexity"] for d in cc_details]
                report.avg_complexity = round(sum(ccs) / len(ccs), 1)
                mx = max(range(len(ccs)), key=lambda i: ccs[i])
                report.max_complexity = ccs[mx]
                report.max_complexity_func = (
                    f"{cc_details[mx]['file']}::{cc_details[mx]['name']}"
                )

            if err or report.tool_errors.get("radon-mi") or report.tool_errors.get("radon-raw"):
                first_error = err or report.tool_errors.get("radon-mi") or report.tool_errors.get("radon-raw")
                report.tool_scores[name] = unavailable_tool_score(first_error)
            else:
                report.tool_scores[name] = compute_tool_score_map(
                    name,
                    maintainability_index=report.maintainability_index,
                    avg_complexity=report.avg_complexity,
                    max_complexity=report.max_complexity,
                    block_count=len(cc_details),
                )

        elif name == "vulture":
            issues, err = run_vulture(py_files)
            report.issues.extend(issues)
            report.dead_code_count = len(issues)
            if err:
                report.tool_scores[name] = unavailable_tool_score(err)
            else:
                report.tool_scores[name] = compute_tool_score_map(name, issues=issues)
            if err: report.tool_errors[name] = err

        elif name == "mypy":
            issues, err = run_mypy(py_files)
            report.issues.extend(issues)
            report.type_errors = len([i for i in issues if i.severity != "INFO"])
            if err:
                report.tool_scores[name] = unavailable_tool_score(err)
            else:
                report.tool_scores[name] = compute_tool_score_map(name, issues=issues)
            if err: report.tool_errors[name] = err

    # Deduplicate (same file + line + message from different tools)
    seen = set()
    deduped = []
    for issue in report.issues:
        key = (issue.file, issue.line, issue.message)
        if key not in seen:
            seen.add(key)
            deduped.append(issue)
    report.issues = deduped

    report.quality_score = compute_quality_score(report)
    report.grade = grade_from_score(report.quality_score)
    report.tool_outputs = list(COMMAND_LOG)

    return report


# ═══════════════════════════════════════════════════════════════════════════════
# TERMINAL REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def bar(value: float, max_val: float, width: int = 20) -> str:
    ratio = value / max(max_val, 1)
    filled = int(ratio * width)
    if NO_COLOR:
        return "█" * filled + "░" * (width - filled)
    color = GREEN if ratio >= 0.65 else YELLOW if ratio >= 0.4 else RED
    return f"{color}{'█' * filled}{DIM}{'░' * (width - filled)}{RESET}"


def fmt_debt(issues: List[Issue]) -> str:
    debt = {"CRITICAL": 60, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "INFO": 0}
    mins = sum(debt.get(i.severity, 0) for i in issues)
    if mins < 60:
        return f"{mins}m"
    h, m = divmod(mins, 60)
    if h < 8:
        return f"{h}h {m}m"
    d, h = divmod(h, 8)
    return f"{d}d {h}h"


def parse_tool_json(value: str):
    if not value.strip():
        return None

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def print_tool_header(name: str, item: dict):
    command = " ".join(item["cmd"])
    returncode = item["returncode"]
    status = c(GREEN, "ok") if returncode == 0 else c(YELLOW, "issues")
    print(f"\n  {c(f'{BOLD}{BLUE}', name)}  {status}")
    print(f"    {c(DIM, command)}")


def print_pylint_details(item: dict):
    data = parse_tool_json(item["stdout"])
    if not data:
        print("    No structured pylint output.")
        return

    messages = data.get("messages", [])
    stats = data.get("statistics", {})
    counts = stats.get("messageTypeCount", {})

    print(f"    Score: {stats.get('score', 'n/a')}/10")
    print(f"    Modules linted: {stats.get('modulesLinted', 'n/a')}")
    print("    Message counts:")
    for key in ["fatal", "error", "warning", "refactor", "convention", "info"]:
        print(f"      {key:<10} {counts.get(key, 0)}")

    if not messages:
        print("    Findings: none")
        return

    print("    Findings:")
    for msg in messages:
        print(
            f"      L{msg.get('line', 0):<4} "
            f"{msg.get('message-id', '?'):<8} {msg.get('message', '')}"
        )


def print_flake8_details(item: dict):
    lines = [line for line in item["stdout"].splitlines() if line.strip()]
    if not lines:
        print("    Findings: none")
        return

    print(f"    Findings: {len(lines)}")
    for line in lines:
        print(f"      {line}")


def print_bandit_details(item: dict):
    data = parse_tool_json(item["stdout"])
    if not data:
        print("    No structured bandit output.")
        return

    totals = data.get("metrics", {}).get("_totals", {})
    results = data.get("results", [])

    print("    Severity:")
    for key in ["HIGH", "MEDIUM", "LOW"]:
        print(f"      {key:<8} {totals.get(f'SEVERITY.{key}', 0)}")
    print("    Confidence:")
    for key in ["HIGH", "MEDIUM", "LOW"]:
        print(f"      {key:<8} {totals.get(f'CONFIDENCE.{key}', 0)}")
    print(f"    Lines scanned: {totals.get('loc', 0)}")

    if not results:
        print("    Findings: none")
        return

    print("    Findings:")
    for result in results:
        print(
            f"      L{result.get('line_number', 0):<4} "
            f"{result.get('test_id', '?'):<6} "
            f"{result.get('issue_severity', '?'):<6} "
            f"{result.get('issue_text', '')}"
        )


def print_radon_cc_details(item: dict):
    data = parse_tool_json(item["stdout"])
    if not data:
        print("    No structured radon complexity output.")
        return

    blocks = []
    for fpath, entries in data.items():
        for entry in entries:
            blocks.append((fpath, entry))

    if not blocks:
        print("    Blocks: none")
        return

    print("    Complexity blocks:")
    for fpath, entry in sorted(
        blocks,
        key=lambda item_entry: item_entry[1].get("complexity", 0),
        reverse=True,
    ):
        print(
            f"      {entry.get('rank', '?')} "
            f"CC={entry.get('complexity', 0):<2} "
            f"L{entry.get('lineno', 0):<4} "
            f"{fpath}::{entry.get('name', '?')}"
        )


def print_radon_mi_details(item: dict):
    data = parse_tool_json(item["stdout"])
    if not data:
        print("    No structured radon maintainability output.")
        return

    print("    Maintainability index:")
    for fpath, info in data.items():
        if isinstance(info, dict):
            print(f"      {fpath}: {info.get('mi', 0):.1f} ({info.get('rank', '?')})")
        else:
            print(f"      {fpath}: {info}")


def print_radon_raw_details(item: dict):
    data = parse_tool_json(item["stdout"])
    if not data:
        print("    No structured radon raw-metrics output.")
        return

    print("    Raw metrics:")
    for fpath, info in data.items():
        print(f"      {fpath}")
        for key in ["loc", "sloc", "lloc", "comments", "single_comments", "multi", "blank"]:
            print(f"        {key:<16} {info.get(key, 0)}")


def print_line_tool_details(item: dict, label: str):
    lines = [line for line in item["stdout"].splitlines() if line.strip()]
    if not lines:
        print(f"    {label}: none")
        return

    print(f"    {label}: {len(lines)}")
    for line in lines:
        print(f"      {line}")


def print_tool_outputs(report: Report):
    print(f"\n  {c(f'{BOLD}{WHITE}', '🧾 TOOL DETAILS')}")
    print(f"  {c(DIM, '─' * 68)}")

    for item in report.tool_outputs:
        cmd = item["cmd"]
        tool_name = tool_output_key(cmd)

        if tool_name == "pylint":
            print_tool_header("pylint", item)
            print_pylint_details(item)
        elif tool_name == "flake8":
            print_tool_header("flake8", item)
            print_flake8_details(item)
        elif tool_name == "bandit":
            print_tool_header("bandit", item)
            print_bandit_details(item)
        elif tool_name == "radon-cc":
            print_tool_header("radon complexity", item)
            print_radon_cc_details(item)
        elif tool_name == "radon-mi":
            print_tool_header("radon maintainability", item)
            print_radon_mi_details(item)
        elif tool_name == "radon-raw":
            print_tool_header("radon raw metrics", item)
            print_radon_raw_details(item)
        elif tool_name == "vulture":
            print_tool_header("vulture", item)
            print_line_tool_details(item, "Dead-code findings")
        elif tool_name == "mypy":
            print_tool_header("mypy", item)
            print_line_tool_details(item, "Type findings")

        if item["stderr"].strip():
            print("    Tool messages:")
            for line in item["stderr"].rstrip().splitlines():
                print(f"      {line}")


def print_report(report: Report, verbose: bool = False):
    W = 72
    gc = {"A": GREEN, "B": CYAN, "C": YELLOW, "D": RED, "F": BG_RED + WHITE}.get(report.grade, WHITE)
    sev_colors = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": "\033[33m", "LOW": CYAN, "INFO": GRAY}

    print()
    print(c(f"{BOLD}{BLUE}", "═" * W))
    print(c(f"{BOLD}{BLUE}", "  ⚡ PyQuality — Aggregated Code Quality Report"))
    print(c(f"{BOLD}{BLUE}", "═" * W))
    print()

    # Grade
    print(f"  {c(BOLD, 'Quality Grade:')}  {c(f'{gc}{BOLD}', f'  {report.grade}  ')}"
          f"  {c(BOLD, 'Score:')} {report.quality_score}/100")
    if report.pylint_score is not None:
        print(f"  {c(DIM, f'Pylint score: {report.pylint_score}/10')}")
    print()

    print(f"  {c(f'{BOLD}{WHITE}', '🧮 TOOL SCORES')}")
    print(f"  {c(DIM, '─' * (W - 4))}")
    for name, _, _ in TOOL_DETAILS:
        info = report.tool_scores.get(name)
        if not info:
            continue

        score = info.get("score")
        grade = info.get("grade") or "n/a"
        if score is None:
            print(f"  {name:<16} n/a   {c(DIM, info.get('source', ''))}")
            continue

        raw_value = info.get("raw_value")
        raw_scale = info.get("raw_scale") or ""
        raw_suffix = ""
        if raw_value is not None:
            raw_suffix = f"  {c(DIM, f'raw: {raw_value}{raw_scale}')}"

        print(
            f"  {name:<16} {c(BOLD, f'{score:>5}/100')}  "
            f"{c(DIM, f'grade {grade}')}{raw_suffix}"
        )
    print()

    # Overview
    print(f"  {c(f'{BOLD}{WHITE}', '📊 PROJECT OVERVIEW')}")
    print(f"  {c(DIM, '─' * (W - 4))}")
    print(f"  Files analyzed    {c(BOLD, f'{report.files_analyzed:>6}')}")
    print(f"  Total lines       {c(BOLD, f'{report.total_lines:>6}')}"
          f"   (code: {report.code_lines}, comments: {report.comment_lines}, blank: {report.blank_lines})")
    cp = round(report.comment_lines / max(report.code_lines, 1) * 100, 1)
    print(f"  Comment ratio     {c(BOLD, f'{cp:>5}%')}")
    print()

    # Metrics
    print(f"  {c(f'{BOLD}{WHITE}', '📐 QUALITY METRICS')}")
    print(f"  {c(DIM, '─' * (W - 4))}")
    print(f"  Maintainability   {bar(report.maintainability_index, 100)} {report.maintainability_index}/100")

    cc_inv = max(0, 20 - min(report.avg_complexity, 20))
    print(f"  Avg complexity    {bar(cc_inv, 20)} {report.avg_complexity}")

    if report.max_complexity_func:
        mc_c = YELLOW if report.max_complexity <= 15 else RED
        print(f"  Max complexity    {c(mc_c, str(report.max_complexity))}"
              f"  {c(DIM, report.max_complexity_func)}")

    print(f"  Security issues   {c(GREEN if report.security_issues == 0 else RED, str(report.security_issues))}")
    print(f"  Dead code items   {c(GREEN if report.dead_code_count <= 3 else YELLOW, str(report.dead_code_count))}")
    print(f"  Type errors       {c(GREEN if report.type_errors == 0 else YELLOW, str(report.type_errors))}")
    print(f"  Technical debt    {c(BOLD, fmt_debt(report.issues))}")
    print()

    # Issues by severity
    total = len(report.issues)
    print(f"  {c(f'{BOLD}{WHITE}', f'🔍 ISSUES FOUND: {total}')}")
    print(f"  {c(DIM, '─' * (W - 4))}")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        cnt = sum(1 for i in report.issues if i.severity == sev)
        if cnt > 0:
            print(f"  {c(sev_colors[sev], f'● {sev:<10}')} {cnt:>4}")
    print()

    # By category
    cat_icons = {
        "Bug": "🐛", "Security": "🔓", "Code Smell": "💩", "Style": "🎨",
        "Convention": "📏", "Complexity": "🌀", "Dead Code": "💀",
        "Type Error": "📝", "Info": "ℹ️ ",
    }
    categories = Counter(i.category for i in report.issues)
    for cat, cnt in categories.most_common():
        print(f"  {cat_icons.get(cat, '•')} {cat:<16} {cnt:>4}")
    print()

    # By tool
    print(f"  {c(f'{BOLD}{WHITE}', '🔧 ISSUES BY TOOL')}")
    print(f"  {c(DIM, '─' * (W - 4))}")
    tools = Counter(i.tool for i in report.issues)
    for tool, cnt in tools.most_common():
        print(f"  {tool:<16} {cnt:>4}")
    print()

    # Verbose detail
    if verbose and report.issues:
        print(f"  {c(f'{BOLD}{WHITE}', '📋 DETAILED ISSUES')}")
        print(f"  {c(DIM, '─' * (W - 4))}")

        by_file = defaultdict(list)
        for issue in report.issues:
            by_file[issue.file].append(issue)

        for fpath, issues in sorted(by_file.items()):
            print(f"\n  {c(f'{BOLD}{BLUE}', f'▸ {fpath}')}")
            for issue in sorted(issues, key=lambda i: i.line):
                sc = sev_colors.get(issue.severity, "")
                print(f"    {c(sc, f'{issue.severity:<8}')} L{issue.line:<4} "
                      f"{c(DIM, f'[{issue.tool}:{issue.code}]')} {issue.message}")

    if verbose:
        print_tool_outputs(report)

    # Tool errors
    if report.tool_errors:
        print(f"\n  {c(f'{BOLD}{YELLOW}', '⚠ TOOL WARNINGS')}")
        for tool, err in report.tool_errors.items():
            print(f"  {tool}: {c(DIM, err)}")

    # Footer
    print()
    print(f"  {c(DIM, '─' * (W - 4))}")
    if report.grade in ("A", "B"):
        print(f"  {c(f'{GREEN}{BOLD}', '✅ Quality Gate: PASSED')}")
    elif report.grade == "C":
        print(f"  {c(f'{YELLOW}{BOLD}', '⚠️  Quality Gate: WARNING')}")
    else:
        print(f"  {c(f'{RED}{BOLD}', '❌ Quality Gate: FAILED')}")

    if not verbose:
        print(f"  {c(DIM, 'Run with -v for full issue details')}")
    print(f"  {c(DIM, 'Powered by: pylint + flake8 + bandit + radon + vulture + mypy')}")
    print(c(f"{BOLD}{BLUE}", "═" * W))
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# JSON OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════

def issue_to_dict(issue: Issue) -> Dict[str, object]:
    return {
        "tool": issue.tool,
        "file": issue.file,
        "line": issue.line,
        "severity": issue.severity,
        "code": issue.code,
        "message": issue.message,
        "category": issue.category,
    }


def build_report_payload(report: Report) -> Dict[str, object]:
    return {
        "quality_score": report.quality_score,
        "grade": report.grade,
        "path": report.path,
        "analyzed_files": report.analyzed_files,
        "pylint_score": report.pylint_score,
        "tool_scores": report.tool_scores,
        "tool_errors": report.tool_errors,
        "metrics": {
            "files_analyzed": report.files_analyzed,
            "total_lines": report.total_lines,
            "code_lines": report.code_lines,
            "comment_lines": report.comment_lines,
            "blank_lines": report.blank_lines,
            "avg_complexity": report.avg_complexity,
            "max_complexity": report.max_complexity,
            "maintainability_index": report.maintainability_index,
            "security_issues": report.security_issues,
            "dead_code_items": report.dead_code_count,
            "type_errors": report.type_errors,
        },
        "issues_summary": {
            "total": len(report.issues),
            "by_severity": dict(Counter(i.severity for i in report.issues)),
            "by_category": dict(Counter(i.category for i in report.issues)),
            "by_tool": dict(Counter(i.tool for i in report.issues)),
        },
        "tool_outputs": report.tool_outputs,
        "issues": [issue_to_dict(issue) for issue in report.issues],
    }


def output_json(report: Report):
    print(json.dumps(build_report_payload(report), indent=2))


def tool_output_key(cmd: Sequence[str]) -> str:
    if not cmd:
        return "unknown"

    tool_name = Path(cmd[0]).name
    if tool_name == "radon" and len(cmd) > 1:
        return f"{tool_name}-{cmd[1]}"
    return tool_name


def output_group_name(output_key: str) -> str:
    if output_key.startswith("radon-"):
        return "radon"
    return output_key


def render_score_label(score_info: Optional[dict]) -> str:
    if not score_info or score_info.get("score") is None:
        return "n/a"

    score = score_info["score"]
    grade = score_info.get("grade") or "n/a"
    return f"{score}/100 ({grade})"


def tool_issues(report: Report, tool_name: str) -> List[Issue]:
    return [issue for issue in report.issues if issue.tool == tool_name]


def tool_errors(report: Report, tool_name: str) -> Dict[str, str]:
    if tool_name == "radon":
        return {
            name: error
            for name, error in report.tool_errors.items()
            if name == "radon" or name.startswith("radon-")
        }
    return {
        name: error
        for name, error in report.tool_errors.items()
        if name == tool_name
    }


def render_issue_rows_html(issues: Sequence[Issue]) -> str:
    if not issues:
        return "<p>No findings reported.</p>"

    rows = [
        "<table>",
        "<thead><tr><th>Severity</th><th>File</th><th>Line</th><th>Code</th><th>Message</th></tr></thead>",
        "<tbody>",
    ]
    for issue in sorted(issues, key=lambda item: (item.file, item.line, item.code)):
        rows.append(
            "<tr>"
            f"<td>{html_escape(issue.severity)}</td>"
            f"<td>{html_escape(issue.file)}</td>"
            f"<td>{issue.line}</td>"
            f"<td>{html_escape(issue.code)}</td>"
            f"<td>{html_escape(issue.message)}</td>"
            "</tr>"
        )
    rows.extend(["</tbody>", "</table>"])
    return "\n".join(rows)


def render_output_sections_html(artifacts: Sequence[dict]) -> str:
    if not artifacts:
        return "<p>No raw command output captured.</p>"

    sections = []
    for artifact in artifacts:
        links = []
        if artifact.get("meta_file"):
            links.append(f"<a href=\"../{html_escape(artifact['meta_file'])}\">meta</a>")
        if artifact.get("stdout_file"):
            links.append(f"<a href=\"../{html_escape(artifact['stdout_file'])}\">stdout</a>")
        if artifact.get("stderr_file"):
            links.append(f"<a href=\"../{html_escape(artifact['stderr_file'])}\">stderr</a>")
        link_block = " | ".join(links) if links else "no artifact files"

        section = [
            "<section class=\"artifact\">",
            f"<h3>{html_escape(artifact['label'])}</h3>",
            f"<p><strong>Command:</strong> <code>{html_escape(' '.join(artifact['command']))}</code></p>",
            f"<p><strong>Return code:</strong> {artifact['returncode']} | <strong>Files:</strong> {link_block}</p>",
        ]
        stdout = artifact.get("stdout", "").strip()
        stderr = artifact.get("stderr", "").strip()
        if stdout:
            section.append(
                "<details><summary>stdout</summary>"
                f"<pre>{html_escape(artifact['stdout'])}</pre>"
                "</details>"
            )
        if stderr:
            section.append(
                "<details><summary>stderr</summary>"
                f"<pre>{html_escape(artifact['stderr'])}</pre>"
                "</details>"
            )
        section.append("</section>")
        sections.append("\n".join(section))
    return "\n".join(sections)


def render_index_markdown(report: Report, generated_at: str) -> str:
    lines = [
        "# PyQuality Report",
        "",
        f"- Generated at: `{generated_at}`",
        f"- Target: `{report.path}`",
        f"- Files analyzed: `{report.files_analyzed}`",
        f"- Overall score: `{report.quality_score}/100`",
        f"- Grade: `{report.grade}`",
        "- Scoring notes: [scoring-heuristics.md](scoring-heuristics.md)",
        "",
        "## Tool Reports",
        "",
        "| Tool | Score | Details |",
        "| --- | --- | --- |",
    ]
    for tool_name, _, _ in TOOL_DETAILS:
        score_info = report.tool_scores.get(tool_name)
        lines.append(
            f"| `{tool_name}` | `{render_score_label(score_info)}` | "
            f"[html](tools/{tool_name}.html) · [json](tools/{tool_name}.json) |"
        )

    lines.extend([
        "",
        "## Files",
        "",
    ])
    for file_path in report.analyzed_files:
        lines.append(f"- `{file_path}`")

    lines.append("")
    return "\n".join(lines)


def render_index_html(report: Report, generated_at: str) -> str:
    rows = []
    for tool_name, _, _ in TOOL_DETAILS:
        score_info = report.tool_scores.get(tool_name)
        rows.append(
            "<tr>"
            f"<td>{html_escape(tool_name)}</td>"
            f"<td>{html_escape(render_score_label(score_info))}</td>"
            f"<td><a href=\"tools/{html_escape(tool_name)}.html\">html</a> | "
            f"<a href=\"tools/{html_escape(tool_name)}.json\">json</a></td>"
            "</tr>"
        )

    files_html = "\n".join(
        f"<li><code>{html_escape(file_path)}</code></li>"
        for file_path in report.analyzed_files
    ) or "<li><em>No files recorded.</em></li>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PyQuality Report</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; line-height: 1.5; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d0d7de; padding: 0.6rem; text-align: left; vertical-align: top; }}
    code, pre {{ font-family: monospace; }}
    pre {{ background: #f6f8fa; padding: 1rem; overflow: auto; }}
  </style>
</head>
<body>
  <h1>PyQuality Report</h1>
  <p><strong>Generated at:</strong> <code>{html_escape(generated_at)}</code></p>
  <p><strong>Target:</strong> <code>{html_escape(report.path)}</code></p>
  <p><strong>Overall:</strong> {report.quality_score}/100 ({html_escape(report.grade)})</p>
  <p><strong>Scoring notes:</strong> <a href="scoring-heuristics.md">scoring-heuristics.md</a></p>

  <h2>Tool Reports</h2>
  <table>
    <thead><tr><th>Tool</th><th>Score</th><th>Reports</th></tr></thead>
    <tbody>
      {"".join(rows)}
    </tbody>
  </table>

  <h2>Files Analyzed</h2>
  <ul>
    {files_html}
  </ul>
</body>
</html>
"""


def render_tool_html(
    tool_name: str,
    report: Report,
    generated_at: str,
    artifacts: Sequence[dict],
) -> str:
    score_info = report.tool_scores.get(tool_name)
    issues = tool_issues(report, tool_name)
    errors = tool_errors(report, tool_name)
    error_html = ""
    if errors:
        error_items = "".join(
            f"<li><strong>{html_escape(name)}:</strong> {html_escape(error)}</li>"
            for name, error in sorted(errors.items())
        )
        error_html = f"<h2>Tool Warnings</h2><ul>{error_items}</ul>"

    source = ""
    if score_info:
        source = html_escape(str(score_info.get("source", "")))

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PyQuality {html_escape(tool_name)} report</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem auto; max-width: 1200px; padding: 0 1rem; line-height: 1.5; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d0d7de; padding: 0.6rem; text-align: left; vertical-align: top; }}
    code, pre {{ font-family: monospace; }}
    pre {{ background: #f6f8fa; padding: 1rem; overflow: auto; }}
    .artifact {{ border: 1px solid #d0d7de; padding: 1rem; margin: 1rem 0; border-radius: 6px; }}
  </style>
</head>
<body>
  <p><a href="../index.html">Back to index</a></p>
  <h1>{html_escape(tool_name)}</h1>
  <p><strong>Generated at:</strong> <code>{html_escape(generated_at)}</code></p>
  <p><strong>Score:</strong> {html_escape(render_score_label(score_info))}</p>
  <p><strong>Source:</strong> {source or "n/a"}</p>

  <h2>Findings</h2>
  {render_issue_rows_html(issues)}

  {error_html}

  <h2>Raw Tool Output</h2>
  {render_output_sections_html(artifacts)}
</body>
</html>
"""


def render_scoring_heuristics_markdown() -> str:
    return textwrap.dedent("""\
        # PyQuality Scoring Heuristics

        This file explains which scores are native from the underlying tools
        and which scores are derived by PyQuality.

        ## Native Scores

        - `pylint`: native project score reported by pylint itself, on a `/10` scale and normalized by PyQuality to `/100`.

        ## Derived Scores

        The following tools do not provide a single native project score in the
        way PyQuality displays today. PyQuality derives a `/100` value from the
        findings produced by each tool.

        - `flake8`: derived from reported findings.
        - `bandit`: derived from reported findings.
        - `vulture`: derived from reported findings.
        - `mypy`: derived from reported findings.
        - `radon`: derived from native metrics, using the average of:
          - maintainability index
          - a complexity score computed from average cyclomatic complexity

        ## Penalty Model

        For `flake8`, `bandit`, `vulture`, and `mypy`, PyQuality computes:

        - `score = max(0, min(100, 100 - total_penalty))`
        - `total_penalty = sum(penalty_for_each_finding)`

        ### flake8 penalties

        - `HIGH`: 12
        - `MEDIUM`: 6
        - `LOW`: 2
        - `INFO`: 1

        Severity mapping used by PyQuality:

        - `F*` and `E9*` -> `HIGH`
        - `C9*` -> `MEDIUM`
        - `E*` and `W*` -> `LOW`

        ### bandit penalties

        - `CRITICAL`: 35
        - `HIGH`: 20
        - `MEDIUM`: 8
        - `LOW`: 3

        Severity mapping used by PyQuality:

        - Bandit `HIGH` -> PyQuality `CRITICAL`
        - Bandit `MEDIUM` -> PyQuality `HIGH`
        - Bandit `LOW` -> PyQuality `MEDIUM`

        ### vulture penalties

        - `MEDIUM`: 8
        - `LOW`: 4

        Severity mapping used by PyQuality:

        - confidence `>= 90` -> `MEDIUM`
        - confidence `< 90` -> `LOW`

        ### mypy penalties

        - `HIGH`: 20
        - `MEDIUM`: 8
        - `LOW`: 2

        Severity mapping used by PyQuality:

        - `error` -> `HIGH`
        - `warning` -> `MEDIUM`
        - `note` -> `INFO`

        ## Radon Formula

        PyQuality does not use a native radon score. It derives one as:

        - `mi_score = clamp(maintainability_index, 0..100)`
        - `complexity_score` from average complexity bands
        - `radon_score = (mi_score + complexity_score) / 2`

        ## Overall Score

        The overall PyQuality score is also derived. It is the arithmetic mean
        of all per-tool scores that are available in the final report.
    """)


def write_reports(report: Report, reports_dir: str) -> Path:
    report_root = Path(reports_dir)
    tools_dir = report_root / "tools"
    raw_dir = report_root / "raw"
    report_root.mkdir(parents=True, exist_ok=True)
    tools_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()
    payload = build_report_payload(report)
    payload["generated_at"] = generated_at
    (report_root / "summary.json").write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )

    artifacts_by_tool: Dict[str, List[dict]] = defaultdict(list)
    output_counts: Counter[str] = Counter()

    for item in report.tool_outputs:
        output_key = tool_output_key(item.get("cmd", []))
        tool_name = output_group_name(output_key)
        output_counts[output_key] += 1
        suffix = "" if output_counts[output_key] == 1 else f"-{output_counts[output_key]}"
        stem = f"{output_key}{suffix}"

        artifact = {
            "label": output_key,
            "command": item.get("cmd", []),
            "returncode": item.get("returncode"),
            "stdout": item.get("stdout", ""),
            "stderr": item.get("stderr", ""),
        }

        stdout_content = artifact["stdout"].strip()
        if stdout_content:
            parsed_stdout = parse_tool_json(artifact["stdout"])
            stdout_ext = "json" if parsed_stdout is not None else "txt"
            stdout_path = raw_dir / f"{stem}.stdout.{stdout_ext}"
            stdout_value = artifact["stdout"]
            if parsed_stdout is not None:
                stdout_value = json.dumps(parsed_stdout, indent=2)
            stdout_path.write_text(stdout_value, encoding="utf-8")
            artifact["stdout_file"] = stdout_path.relative_to(report_root).as_posix()

        stderr_content = artifact["stderr"].strip()
        if stderr_content:
            stderr_path = raw_dir / f"{stem}.stderr.txt"
            stderr_path.write_text(artifact["stderr"], encoding="utf-8")
            artifact["stderr_file"] = stderr_path.relative_to(report_root).as_posix()

        meta_payload = {
            "label": artifact["label"],
            "command": artifact["command"],
            "returncode": artifact["returncode"],
            "stdout_file": artifact.get("stdout_file"),
            "stderr_file": artifact.get("stderr_file"),
        }
        meta_path = raw_dir / f"{stem}.meta.json"
        meta_path.write_text(json.dumps(meta_payload, indent=2), encoding="utf-8")
        artifact["meta_file"] = meta_path.relative_to(report_root).as_posix()
        artifacts_by_tool[tool_name].append(artifact)

    for tool_name, _, _ in TOOL_DETAILS:
        issues = tool_issues(report, tool_name)
        errors = tool_errors(report, tool_name)
        tool_artifacts = artifacts_by_tool.get(tool_name, [])
        tool_payload = {
            "tool": tool_name,
            "generated_at": generated_at,
            "score": report.tool_scores.get(tool_name),
            "errors": errors,
            "issues": [issue_to_dict(issue) for issue in issues],
            "artifacts": [
                {
                    "label": artifact["label"],
                    "command": artifact["command"],
                    "returncode": artifact["returncode"],
                    "meta_file": artifact.get("meta_file"),
                    "stdout_file": artifact.get("stdout_file"),
                    "stderr_file": artifact.get("stderr_file"),
                }
                for artifact in tool_artifacts
            ],
        }

        (tools_dir / f"{tool_name}.json").write_text(
            json.dumps(tool_payload, indent=2),
            encoding="utf-8",
        )
        (tools_dir / f"{tool_name}.html").write_text(
            render_tool_html(tool_name, report, generated_at, tool_artifacts),
            encoding="utf-8",
        )

    (report_root / "index.md").write_text(
        render_index_markdown(report, generated_at),
        encoding="utf-8",
    )
    (report_root / "index.html").write_text(
        render_index_html(report, generated_at),
        encoding="utf-8",
    )

    scoring_notes_path = report_root / "scoring-heuristics.md"
    if not scoring_notes_path.exists():
        scoring_notes_path.write_text(
            render_scoring_heuristics_markdown(),
            encoding="utf-8",
        )

    return report_root
    print(json.dumps(result, indent=2))


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def print_tool_details():
    print()
    print(c(f"{BOLD}{BLUE}", "PyQuality tool guide"))
    print(c(DIM, "─" * 72))
    for name, summary, detail in TOOL_DETAILS:
        print(f"  {c(BOLD, name):<18} {summary}")
        print(f"  {c(DIM, detail)}")
    print()


def discover_menu_targets() -> List[str]:
    targets = []

    for entry in sorted(Path(".").iterdir(), key=lambda item: item.name):
        if entry.name in SKIP_DIRS:
            continue

        if entry.is_file() and entry.suffix == ".py" and entry.resolve() not in SKIP_PROJECT_FILES:
            targets.append(str(entry))
        elif entry.is_dir() and find_python_files(str(entry)):
            targets.append(str(entry))

    if find_python_files("."):
        targets.append(".")

    return targets


def prompt_index(prompt: str, item_count: int) -> Optional[int]:
    while True:
        choice = input(prompt).strip().lower()
        if choice in {"q", "quit", "exit"}:
            return None

        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= item_count:
                return index - 1

        print(c(YELLOW, f"Choose 1-{item_count}, or q to quit."))


def prompt_analysis_target() -> Optional[str]:
    targets = discover_menu_targets()

    print()
    print(c(f"{BOLD}{BLUE}", "What do you want to analyze?"))
    print(c(DIM, "─" * 72))
    for index, target in enumerate(targets, 1):
        label = "current directory (may include tool output from hidden envs)"
        if target != ".":
            label = target
        print(f"  {index}. {label}")
    print(f"  {len(targets) + 1}. Enter custom path")
    print("  q. Quit")

    selected = prompt_index("Select target: ", len(targets) + 1)
    if selected is None:
        return None

    if selected == len(targets):
        return input("Path to analyze: ").strip()

    return targets[selected]


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"

    while True:
        answer = input(f"{prompt} [{suffix}]: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False

        print(c(YELLOW, "Please answer y or n."))


def run_interactive_menu(args) -> None:
    print(c(f"{BOLD}{BLUE}", "\n⚡ PyQuality interactive menu"))
    print_tool_details()

    while True:
        print(c(f"{BOLD}{WHITE}", "Menu"))
        print("  1. Analyze a Python file or directory")
        print("  2. Show tool details")
        print("  3. Quit")

        selected = prompt_index("Select option: ", 3)
        if selected is None or selected == 2:
            return

        if selected == 1:
            print_tool_details()
            continue

        path = prompt_analysis_target()
        if not path:
            continue

        args.path = path
        args.verbose = prompt_yes_no("Show detailed issues", default=True)
        args.skip_mypy = prompt_yes_no("Skip mypy type checking", default=False)
        run_analysis_from_args(args)
        return


def run_analysis_from_args(args) -> None:
    if not os.path.exists(args.path):
        print(c(RED, f"Error: Path '{args.path}' not found"))
        sys.exit(1)

    report = analyze(
        args.path,
        skip_mypy=args.skip_mypy,
        show_progress=not args.json,
    )
    if args.reports_dir:
        write_reports(report, args.reports_dir)

    if args.json:
        output_json(report)
    else:
        print_report(report, verbose=args.verbose)
        if args.reports_dir:
            print(c(DIM, f"Detailed reports written to {args.reports_dir}"))

    if args.threshold:
        grade_order = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
        if grade_order.get(report.grade, 0) < grade_order.get(args.threshold, 0):
            if not args.json:
                msg = f"Threshold not met: got {report.grade}, required {args.threshold}"
                print(c(RED, msg))
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="pyquality",
        description="⚡ PyQuality — Aggregated Python Code Quality Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Tools orchestrated:
              pylint     Linting, code smells, conventions
              flake8     PEP 8 style + pyflakes errors
              bandit     Security vulnerability scanning
              radon      Cyclomatic complexity & maintainability
              vulture    Dead code detection
              mypy       Static type checking

            Examples:
              pyquality .                   Analyze current directory
              pyquality src/ -v             Show all issues in detail
              pyquality app.py --json       JSON output for CI pipelines
              pyquality src/ -t B           Fail if grade drops below B
              pyquality src/ --skip-mypy    Skip type checking (faster)
              pyquality . --reports-dir docs/quality
                                          Export markdown/html/json reports
        """)
    )
    parser.add_argument("path", nargs="?",
                        help="Python file or directory to analyze")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed issue listing")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("-t", "--threshold", default=None,
                        choices=["A", "B", "C", "D"],
                        help="Fail (exit 1) if grade is below threshold")
    parser.add_argument("--skip-mypy", action="store_true",
                        help="Skip mypy type checking (faster)")
    parser.add_argument("--reports-dir", default=None,
                        help="Write detailed report artifacts to a directory")

    args = parser.parse_args()

    if args.path is None:
        run_interactive_menu(args)
        return

    run_analysis_from_args(args)


if __name__ == "__main__":
    main()
