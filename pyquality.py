#!/usr/bin/env python3
"""
PyQuality — Aggregated Python Code Quality CLI
================================================
Orchestrates industry-standard tools and unifies their output
into a single quality report with an overall grade.

Tools used:
  • pylint     — Linting, code smells, conventions, refactoring hints
  • flake8     — PEP 8 style + pyflakes logical errors
  • ruff       — Fast aggregated lint rules across many Python ecosystems
  • prospector — Aggregated Python static analysis across multiple checkers
  • bandit     — Security vulnerability scanning
  • semgrep    — Pattern-based bug and security scanning
  • pydeps     — Import graph and dependency structure analysis
  • radon      — Cyclomatic complexity & maintainability index
  • vulture    — Dead code detection
  • mypy       — Static type checking

Usage:
    python pyquality.py <path>                # Analyze file or directory
    python pyquality.py <path> -v             # Verbose (show all issues)
    python pyquality.py <path> --json         # JSON output
    python pyquality.py <path> -t B           # Fail if grade < B

Requirements:
    pip install pylint flake8 ruff prospector bandit semgrep pydeps radon vulture mypy
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from datetime import datetime, timezone
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from html import escape as html_escape
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Tuple


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

BUNDLED_SEMGREP_RULES = textwrap.dedent("""\
rules:
  - id: pyquality.eval-use
    message: Avoid eval(); it executes arbitrary code.
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
    pattern: eval(...)

  - id: pyquality.exec-use
    message: Avoid exec(); it executes arbitrary code.
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
    pattern: exec(...)

  - id: pyquality.subprocess-shell-true
    message: Avoid subprocess calls with shell=True.
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      confidence: HIGH
      impact: HIGH
    patterns:
      - pattern-either:
          - pattern: subprocess.run(..., shell=True, ...)
          - pattern: subprocess.call(..., shell=True, ...)
          - pattern: subprocess.Popen(..., shell=True, ...)
          - pattern: subprocess.check_call(..., shell=True, ...)
          - pattern: subprocess.check_output(..., shell=True, ...)

  - id: pyquality.unsafe-yaml-load
    message: Prefer yaml.safe_load() over yaml.load().
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      confidence: MEDIUM
      impact: HIGH
    pattern: yaml.load(...)

  - id: pyquality.pickle-load
    message: Avoid loading untrusted pickle data.
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      confidence: MEDIUM
      impact: HIGH
    pattern-either:
      - pattern: pickle.load(...)
      - pattern: pickle.loads(...)

  - id: pyquality.tempfile-mktemp
    message: tempfile.mktemp() is insecure; use NamedTemporaryFile or mkstemp.
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      confidence: HIGH
      impact: MEDIUM
    pattern: tempfile.mktemp(...)

  - id: pyquality.requests-without-timeout
    message: Add an explicit timeout to requests calls.
    severity: WARNING
    languages: [python]
    metadata:
      category: bug
      confidence: MEDIUM
      impact: MEDIUM
    patterns:
      - pattern: requests.$METHOD(...)
      - pattern-not: requests.$METHOD(..., timeout=..., ...)

  - id: pyquality.weak-hashlib
    message: Avoid weak hashes like MD5 and SHA1 for security-sensitive code.
    severity: WARNING
    languages: [python]
    metadata:
      category: security
      confidence: HIGH
      impact: MEDIUM
    pattern-either:
      - pattern: hashlib.md5(...)
      - pattern: hashlib.sha1(...)
""")


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
    pydeps_metrics: Dict[str, object] = field(default_factory=dict)
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
        "ruff",
        "Fast lint aggregation",
        "Runs a broad, modern Python rule set quickly, covering flake8 families and many plugin-style checks.",
    ),
    (
        "prospector",
        "Aggregated static analysis",
        "Runs a configured bundle of Python analyzers and profiles with one report.",
    ),
    (
        "bandit",
        "Security scanning",
        "Looks for risky Python patterns such as unsafe subprocess, debug servers, and weak crypto.",
    ),
    (
        "semgrep",
        "Pattern-based code scanning",
        "Finds bug and security patterns using Semgrep rulesets, useful where Bandit's built-ins are narrower.",
    ),
    (
        "pydeps",
        "Import graph structure",
        "Builds a Python import graph to surface cycles, fan-in, fan-out, and coupling hot spots.",
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


def ensure_bundled_semgrep_config() -> str:
    semgrep_dir = Path(tempfile.gettempdir()) / "pyquality-semgrep"
    semgrep_dir.mkdir(parents=True, exist_ok=True)
    config_path = semgrep_dir / "bundled-rules.yml"
    if not config_path.exists() or config_path.read_text(encoding="utf-8") != BUNDLED_SEMGREP_RULES:
        config_path.write_text(BUNDLED_SEMGREP_RULES, encoding="utf-8")
    return str(config_path)


def as_str(value: object, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def merge_env(overrides: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    if not overrides:
        return None

    merged = os.environ.copy()
    merged.update(overrides)
    return merged


def discover_package_roots(path: str) -> List[Path]:
    target = Path(path).resolve()

    def top_package_dir(start: Path) -> Optional[Path]:
        current = start
        package_root = None
        while (current / "__init__.py").exists():
            package_root = current
            parent = current.parent
            if parent == current:
                break
            current = parent
        return package_root

    if target.is_file():
        root = top_package_dir(target.parent)
        return [root] if root else []

    if not target.is_dir():
        return []

    if (target / "__init__.py").exists():
        return [target]

    roots: List[Path] = []
    seen: set[Path] = set()
    for init_file in sorted(target.rglob("__init__.py")):
        package_dir = init_file.parent
        parent = package_dir.parent
        nested = False
        while parent != parent.parent and parent != target:
            if (parent / "__init__.py").exists():
                nested = True
                break
            parent = parent.parent
        if nested or package_dir in seen:
            continue
        roots.append(package_dir)
        seen.add(package_dir)

    return roots


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


def run_cmd(
    cmd: List[str],
    timeout: int = 120,
    *,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    display_cmd: Optional[List[str]] = None,
) -> Tuple[str, str, int]:
    """Roda cmd e registra em COMMAND_LOG.

    display_cmd: cmd "lógico" pra logar (ex: ["pydeps", path] mesmo quando o
    subprocess real é `python -c <script>`). Permite que tool_output_key
    identifique a ferramenta corretamente.
    """
    effective_env = merge_env(env)
    logged_cmd = display_cmd if display_cmd is not None else cmd
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=effective_env,
        )
        COMMAND_LOG.append({
            "cmd": logged_cmd,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        })
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        stderr = f"Tool not found: {cmd[0]}"
        COMMAND_LOG.append({
            "cmd": logged_cmd,
            "stdout": "",
            "stderr": stderr,
            "returncode": -1,
        })
        return "", stderr, -1
    except subprocess.TimeoutExpired:
        stderr = f"Timeout after {timeout}s"
        COMMAND_LOG.append({
            "cmd": logged_cmd,
            "stdout": "",
            "stderr": stderr,
            "returncode": -1,
        })
        return "", stderr, -1


def classify_ruff_issue(code: str) -> Tuple[str, str]:
    if code.startswith("S"):
        return "HIGH", "Security"
    if code.startswith(("F", "B", "BLE", "PLE", "PLC")) or code.startswith("E9"):
        return "HIGH", "Bug"
    if code.startswith(("C90", "PLR09")):
        return "MEDIUM", "Complexity"
    if code.startswith(("E", "W", "I")):
        return "LOW", "Style"
    return "MEDIUM", "Code Smell"


def classify_semgrep_issue(result: Dict[str, object]) -> Tuple[str, str]:
    extra = result.get("extra", {})
    if not isinstance(extra, dict):
        extra = {}
    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    category = as_str(metadata.get("category")).lower()
    severity_name = as_str(extra.get("severity"), "WARNING").upper()
    severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    severity = severity_map.get(severity_name, "MEDIUM")
    issue_category = "Security" if category == "security" else "Bug"

    if issue_category == "Security" and severity == "HIGH":
        impact = as_str(metadata.get("impact")).upper()
        confidence = as_str(metadata.get("confidence")).upper()
        if impact == "HIGH" and confidence == "HIGH":
            severity = "CRITICAL"

    return severity, issue_category


def classify_prospector_issue(source: str, code: str, message: str) -> Tuple[str, str]:
    normalized_source = source.lower()
    normalized_code = code.upper()
    normalized_message = message.lower()

    if normalized_source == "bandit":
        if normalized_code.startswith("B"):
            return "HIGH", "Security"
        return "MEDIUM", "Security"
    if normalized_source == "dodgy":
        return "HIGH", "Security"
    if normalized_source == "mccabe":
        return "MEDIUM", "Complexity"
    if normalized_source == "vulture":
        return "LOW", "Dead Code"
    if normalized_source in {"mypy", "pyright"}:
        return "HIGH", "Type Error"
    if normalized_source == "pydocstyle":
        return "LOW", "Convention"
    if normalized_source == "pycodestyle":
        if normalized_code.startswith("E9"):
            return "HIGH", "Bug"
        if normalized_code.startswith(("E", "W")):
            return "LOW", "Style"
        return "MEDIUM", "Style"
    if normalized_source == "pyflakes":
        return "HIGH", "Bug"
    if normalized_source == "pylint":
        if normalized_code.startswith(("E", "F")):
            return "HIGH", "Bug"
        if normalized_code.startswith("W"):
            return "MEDIUM", "Bug"
        if normalized_code.startswith("R"):
            return "LOW", "Code Smell"
        if normalized_code.startswith("C"):
            return "LOW", "Convention"
        if any(token in normalized_message for token in ("undefined", "unreachable", "not available", "import error")):
            return "HIGH", "Bug"
        if any(token in normalized_message for token in ("unused", "cell variable", "subprocess.run")):
            return "MEDIUM", "Bug"
        if normalized_code.startswith("TOO-MANY-") or normalized_code == "DISALLOWED-NAME":
            return "LOW", "Code Smell"
        return "MEDIUM", "Code Smell"

    if "security" in normalized_message or "password" in normalized_message or "secret" in normalized_message:
        return "HIGH", "Security"
    return "MEDIUM", "Code Smell"


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

# Ordem importa: prefixos mais específicos antes dos genéricos (E9 antes de E).
FLAKE8_RULES: List[Tuple[Tuple[str, ...], Tuple[str, str]]] = [
    (("E9", "F"),  ("HIGH",   "Bug")),
    (("C9",),      ("MEDIUM", "Complexity")),
    (("E", "W"),   ("LOW",    "Style")),
]


def classify_flake8(code: str) -> Tuple[str, str]:
    for prefixes, result in FLAKE8_RULES:
        if code.startswith(prefixes):
            return result
    return ("LOW", "Style")


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
            severity, category = classify_flake8(code)

            issues.append(Issue(
                tool="flake8", file=fpath, line=int(lineno),
                col=int(col), severity=severity, code=code,
                message=message.strip(), category=category,
            ))

    return issues, None


# ── RUFF ────────────────────────────────────────────────────────────────────

def run_ruff(files: List[str]) -> Tuple[List[Issue], Optional[str]]:
    cmd = [
        resolve_tool_path("ruff"),
        "check",
        "--output-format=json",
        "--exit-zero",
        *files,
    ]
    stdout, stderr, rc = run_cmd(cmd)
    issues: List[Issue] = []

    if rc == -1:
        return issues, stderr or "Failed to run ruff"

    if rc not in (0,) and not stdout.strip():
        return issues, stderr or "Ruff failed"

    if not stdout.strip():
        return issues, None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return issues, "Failed to parse ruff output"

    if not isinstance(data, list):
        return issues, "Unexpected ruff output format"

    for item in data:
        if not isinstance(item, dict):
            continue
        code = as_str(item.get("code"), "?")
        location = item.get("location", {})
        if not isinstance(location, dict):
            location = {}
        severity, category = classify_ruff_issue(code)
        issues.append(Issue(
            tool="ruff",
            file=as_str(item.get("filename"), default_issue_file(files)),
            line=int(location.get("row", 0) or 0),
            col=int(location.get("column", 0) or 0),
            severity=severity,
            code=code,
            message=as_str(item.get("message")),
            category=category,
        ))

    return issues, None


# ── PROSPECTOR ──────────────────────────────────────────────────────────────

def run_prospector(files: List[str], strictness: str = "medium") -> Tuple[List[Issue], Optional[str]]:
    cmd = [
        resolve_tool_path("prospector"),
        "--output-format", "json",
        "--strictness", strictness,
        *files,
    ]
    stdout, stderr, rc = run_cmd(cmd, timeout=240)
    issues: List[Issue] = []

    if rc == -1:
        return issues, stderr or "Failed to run prospector"

    if rc not in (0, 1) and not stdout.strip():
        return issues, stderr or "Prospector failed"

    if not stdout.strip():
        return issues, None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return issues, "Failed to parse prospector output"

    if isinstance(data, dict):
        messages = data.get("messages", [])
    elif isinstance(data, list):
        messages = data
    else:
        return issues, "Unexpected prospector output format"

    if not isinstance(messages, list):
        return issues, "Unexpected prospector messages format"

    for item in messages:
        if not isinstance(item, dict):
            continue

        location = item.get("location", {})
        if not isinstance(location, dict):
            location = {}

        path_value = (
            location.get("path")
            or item.get("path")
            or item.get("file")
            or default_issue_file(files)
        )
        line_value = location.get("line") or item.get("line") or 0
        col_value = (
            location.get("character")
            or location.get("column")
            or item.get("character")
            or item.get("column")
            or 0
        )
        source = as_str(item.get("source"), "prospector")
        code = as_str(item.get("code"), "prospector")
        if code.lower() in PROSPECTOR_NOISE_CODES:
            continue
        message = as_str(item.get("message"))
        severity, category = classify_prospector_issue(source, code, message)

        issues.append(Issue(
            tool="prospector",
            file=as_str(path_value, default_issue_file(files)),
            line=int(line_value or 0),
            col=int(col_value or 0),
            severity=severity,
            code=f"{source}:{code}" if source and code else code or source or "prospector",
            message=message,
            category=category,
        ))

    return issues, None


# Codes que prospector emite por causa de plugins ausentes (ex: pylint-django
# não instalado) — ruído, não problema do código analisado.
PROSPECTOR_NOISE_CODES = {
    "django-not-available",
    "flask-not-available",
    "celery-not-available",
}


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


# ── SEMGREP ─────────────────────────────────────────────────────────────────

def run_semgrep(files: List[str], config: Optional[str] = None) -> Tuple[List[Issue], Optional[str]]:
    effective_config = config or ensure_bundled_semgrep_config()
    cmd = [
        resolve_tool_path("semgrep"),
        "scan",
        "--config", effective_config,
        "--metrics=off",
        "--disable-version-check",
        "--quiet",
        "--json",
        *files,
    ]
    semgrep_dir = Path(tempfile.gettempdir()) / "pyquality-semgrep"
    semgrep_settings = semgrep_dir / "settings.yaml"
    semgrep_log = semgrep_dir / "semgrep.log"
    stdout, stderr, rc = run_cmd(
        cmd,
        timeout=240,
        env={
            "XDG_CONFIG_HOME": str(semgrep_dir),
            "SEMGREP_SETTINGS_FILE": str(semgrep_settings),
            "SEMGREP_LOG_FILE": str(semgrep_log),
        },
    )
    issues: List[Issue] = []

    if rc == -1:
        return issues, stderr or "Failed to run semgrep"

    if rc not in (0,) and not stdout.strip():
        return issues, stderr or "Semgrep failed"

    if not stdout.strip():
        return issues, None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return issues, "Failed to parse semgrep output"

    if not isinstance(data, dict):
        return issues, "Unexpected semgrep output format"

    results = data.get("results", [])
    if not isinstance(results, list):
        return issues, "Unexpected semgrep results format"

    for result in results:
        if not isinstance(result, dict):
            continue
        start = result.get("start", {})
        if not isinstance(start, dict):
            start = {}
        extra = result.get("extra", {})
        if not isinstance(extra, dict):
            extra = {}
        severity, category = classify_semgrep_issue(result)
        issues.append(Issue(
            tool="semgrep",
            file=as_str(result.get("path"), default_issue_file(files)),
            line=int(start.get("line", 0) or 0),
            col=int(start.get("col", 0) or 0),
            severity=severity,
            code=as_str(result.get("check_id"), "semgrep"),
            message=as_str(extra.get("message")),
            category=category,
        ))

    errors = data.get("errors", [])
    if errors:
        messages = []
        for error in errors:
            if isinstance(error, dict):
                messages.append(as_str(error.get("message")))
            else:
                messages.append(as_str(error))
        message = "; ".join(item for item in messages if item)
        if message:
            return issues, message

    return issues, None


# ── PYDEPS ──────────────────────────────────────────────────────────────────

PYDEPS_HELPER_SCRIPT = r"""
import json, sys
from pydeps import cli
from pydeps.target import Target
from pydeps.py2depgraph import py2dep

argv = ['pydeps', sys.argv[1], '--no-output', '--nodot', '--max-bacon', '0']
args = cli.parse_args(argv[1:])
fname = args.pop('fname')
target = Target(fname)
target.chdir_work()
graph = py2dep(target, **args)
graph.find_import_cycles()

modules = {}
for name, src in graph.sources.items():
    path = getattr(src, 'path', None)
    if not path:
        continue
    modules[name] = {
        'path': path,
        'imports': list(getattr(src, 'imports', []) or []),
        'imported_by': list(getattr(src, 'imported_by', []) or []),
    }

cycles = [[n.name for n in c] for c in getattr(graph, 'cycles', []) or []]
json.dump({'modules': modules, 'cycles': cycles}, sys.stdout)
"""


def run_pydeps(path: str) -> Tuple[List[Issue], Dict[str, object], Optional[str]]:
    package_roots = discover_package_roots(path)
    if not package_roots:
        return [], {}, "Pydeps requires at least one package directory with __init__.py."

    internal_modules: Dict[str, dict] = {}
    cycles: List[List[str]] = []

    for package_root in package_roots:
        cmd = [sys.executable, "-c", PYDEPS_HELPER_SCRIPT, str(package_root)]
        stdout, stderr, rc = run_cmd(
            cmd,
            timeout=240,
            display_cmd=["pydeps", str(package_root)],
        )
        if rc == -1:
            return [], {}, stderr or "Failed to run pydeps"
        if not stdout.strip():
            if stderr.strip():
                return [], {}, stderr or "Pydeps failed"
            continue
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return [], {}, "Failed to parse pydeps output"

        for name, info in (data.get("modules") or {}).items():
            if isinstance(info, dict) and info.get("path"):
                internal_modules[name] = info
        for cycle in data.get("cycles") or []:
            if isinstance(cycle, list) and len(cycle) > 1:
                cycles.append(sorted(str(n) for n in cycle))

    if not internal_modules:
        return [], {}, "Pydeps found no internal package graph for the selected target."

    edge_set: set[Tuple[str, str]] = set()
    fan_in: Counter[str] = Counter()
    fan_out: Counter[str] = Counter()

    for module_name, info in internal_modules.items():
        imports = info.get("imports", []) or []
        for imported in imports:
            imported_name = as_str(imported)
            if imported_name not in internal_modules or imported_name == module_name:
                continue
            edge = (module_name, imported_name)
            if edge in edge_set:
                continue
            edge_set.add(edge)
            fan_out[module_name] += 1
            fan_in[imported_name] += 1

    max_fan_out_module = max(fan_out, key=fan_out.get, default="")
    max_fan_in_module = max(fan_in, key=fan_in.get, default="")
    metrics = {
        "package_roots": [str(root) for root in package_roots],
        "modules": len(internal_modules),
        "edges": len(edge_set),
        "cycle_groups": len(cycles),
        "cycle_modules": sum(len(component) for component in cycles),
        "avg_out_degree": round(len(edge_set) / max(len(internal_modules), 1), 2),
        "max_fan_out": fan_out.get(max_fan_out_module, 0),
        "max_fan_out_module": max_fan_out_module,
        "max_fan_in": fan_in.get(max_fan_in_module, 0),
        "max_fan_in_module": max_fan_in_module,
        "cycles": cycles,
    }

    issues: List[Issue] = []
    for component in cycles:
        module_name = component[0]
        info = internal_modules.get(module_name, {})
        issues.append(Issue(
            tool="pydeps",
            file=as_str(info.get("path"), default_issue_file([path])),
            line=0,
            col=0,
            severity="HIGH" if len(component) >= 4 else "MEDIUM",
            code="PYDEPS-CYCLE",
            message=f"Import cycle across {len(component)} modules: {', '.join(component)}",
            category="Complexity",
        ))

    if metrics["max_fan_out"] >= 10:
        module_name = metrics["max_fan_out_module"]
        info = internal_modules.get(module_name, {})
        issues.append(Issue(
            tool="pydeps",
            file=as_str(info.get("path"), default_issue_file([path])),
            line=0,
            col=0,
            severity="MEDIUM" if metrics["max_fan_out"] >= 14 else "LOW",
            code="PYDEPS-FANOUT",
            message=f"Module '{module_name}' imports {metrics['max_fan_out']} internal modules.",
            category="Code Smell",
        ))

    if metrics["max_fan_in"] >= 12:
        module_name = metrics["max_fan_in_module"]
        info = internal_modules.get(module_name, {})
        issues.append(Issue(
            tool="pydeps",
            file=as_str(info.get("path"), default_issue_file([path])),
            line=0,
            col=0,
            severity="LOW",
            code="PYDEPS-FANIN",
            message=f"Module '{module_name}' is imported by {metrics['max_fan_in']} internal modules.",
            category="Code Smell",
        ))

    return issues, metrics, None


# ── RADON ───────────────────────────────────────────────────────────────────

def severity_for_cc(cc: int) -> Optional[str]:
    if cc > 15:
        return "HIGH"
    if cc > 10:
        return "MEDIUM"
    return None


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
            sev = severity_for_cc(cc)
            if sev:
                issues.append(Issue(
                    tool="radon", file=fpath, line=lineno, col=0,
                    severity=sev, code=f"CC-{rank}",
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
    mi_score = clamp_score(score_maintainability_index(
        maintainability_index if maintainability_index is not None else 100.0
    ))
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
    "ruff": (
        {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 1},
        "Score derivado apenas das ocorrencias reportadas pelo ruff.",
    ),
    "prospector": (
        {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 1},
        "Score derivado apenas das ocorrencias reportadas pelo prospector.",
    ),
    "bandit": (
        {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 8, "LOW": 3},
        "Score derivado apenas das vulnerabilidades reportadas pelo bandit.",
    ),
    "semgrep": (
        {"CRITICAL": 35, "HIGH": 18, "MEDIUM": 8, "LOW": 3},
        "Score derivado apenas das ocorrencias reportadas pelo semgrep.",
    ),
    "vulture": (
        {"MEDIUM": 8, "LOW": 4},
        "Score derivado apenas dos itens de codigo morto reportados pelo vulture.",
    ),
    "mypy": (
        {"HIGH": 20, "MEDIUM": 8, "LOW": 2},
        "Score derivado apenas dos erros e avisos reportados pelo mypy.",
    ),
    "pydeps": (
        {"HIGH": 15, "MEDIUM": 6, "LOW": 2},
        "Score derivado dos ciclos de import e hot spots de acoplamento reportados pelo pydeps.",
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

class ToolAdapter(Protocol):
    """Contrato pra adapter: roda ferramenta, devolve dados normalizados.

    Returns:
        (issues, attrs, score_kwargs, err)
        - issues: lista de Issue pra report.issues.extend(...)
        - attrs:  campos do Report pra setattr (ex: {"pylint_score": 8.5})
        - score_kwargs: kwargs extras pra compute_tool_score_map
        - err: msg de erro ou None
    """
    def __call__(
        self,
        files: List[str],
        **opts: Any,
    ) -> Tuple[List[Issue], Dict[str, Any], Dict[str, Any], Optional[str]]:
        ...


def _wrap_simple(fn: Callable[[List[str]], Tuple[List[Issue], Optional[str]]]) -> ToolAdapter:
    def adapter(files: List[str], **_: Any):
        issues, err = fn(files)
        return issues, {}, {}, err
    return adapter


def _adapt_pylint(files: List[str], **_: Any):
    issues, score, err = run_pylint(files)
    return issues, {"pylint_score": score}, {"pylint_score": score}, err


def _adapt_prospector(files: List[str], **opts: Any):
    issues, err = run_prospector(files, opts["prospector_strictness"])
    return issues, {}, {}, err


def _adapt_semgrep(files: List[str], **opts: Any):
    issues, err = run_semgrep(files, opts["semgrep_config"])
    return issues, {}, {}, err


def _adapt_pydeps(files: List[str], **opts: Any):
    # Pydeps opera sobre o diretório-raiz, não na lista de arquivos.
    issues, metrics, err = run_pydeps(opts["path"])
    return issues, {"pydeps_metrics": metrics}, {}, err


SIMPLE_RUNNERS: Dict[str, ToolAdapter] = {
    "pylint":     _adapt_pylint,
    "flake8":     _wrap_simple(run_flake8),
    "ruff":       _wrap_simple(run_ruff),
    "prospector": _adapt_prospector,
    "bandit":     _wrap_simple(run_bandit),
    "semgrep":    _adapt_semgrep,
    "pydeps":     _adapt_pydeps,
    "vulture":    _wrap_simple(run_vulture),
    "mypy":       _wrap_simple(run_mypy),
}


def _run_radon_bundle(py_files: List[str], report: Report) -> None:
    """Radon roda 3 subcommandos e agrega métricas. Mutates report direto."""
    cc_issues, cc_details, err_cc = run_radon_cc(py_files)
    report.issues.extend(cc_issues)
    report.radon_details = cc_details
    if err_cc:
        report.tool_errors["radon-cc"] = err_cc

    mi, err_mi = run_radon_mi(py_files)
    report.maintainability_index = mi
    if err_mi:
        report.tool_errors["radon-mi"] = err_mi

    raw, err_raw = run_radon_raw(py_files)
    report.total_lines = raw["loc"]
    report.code_lines = raw["sloc"]
    report.comment_lines = raw["comments"] + raw["multi"]
    report.blank_lines = raw["blank"]
    if err_raw:
        report.tool_errors["radon-raw"] = err_raw

    if cc_details:
        ccs = [d["complexity"] for d in cc_details]
        report.avg_complexity = round(sum(ccs) / len(ccs), 1)
        mx = max(range(len(ccs)), key=lambda i: ccs[i])
        report.max_complexity = ccs[mx]
        report.max_complexity_func = f"{cc_details[mx]['file']}::{cc_details[mx]['name']}"

    first_err = err_cc or err_mi or err_raw
    if first_err:
        report.tool_scores["radon"] = unavailable_tool_score(first_err)
    else:
        report.tool_scores["radon"] = compute_tool_score_map(
            "radon",
            maintainability_index=report.maintainability_index,
            avg_complexity=report.avg_complexity,
            max_complexity=report.max_complexity,
            block_count=len(cc_details),
        )


def analyze(
    path: str,
    skip_mypy: bool = False,
    show_progress: bool = True,
    semgrep_config: Optional[str] = None,
    prospector_strictness: str = "medium",
) -> Report:
    COMMAND_LOG.clear()
    report = Report(path=path)
    py_files = find_python_files(path)
    report.analyzed_files = py_files
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

        if name == "radon":
            _run_radon_bundle(py_files, report)
            continue

        adapter = SIMPLE_RUNNERS.get(name)
        if adapter is None:
            continue  # tool sem runner registrado

        issues, attrs, score_kwargs, err = adapter(
            py_files,
            path=path,
            prospector_strictness=prospector_strictness,
            semgrep_config=semgrep_config,
        )
        report.issues.extend(issues)
        for k, v in attrs.items():
            setattr(report, k, v)

        if err:
            report.tool_scores[name] = unavailable_tool_score(err)
            report.tool_errors[name] = err
        else:
            report.tool_scores[name] = compute_tool_score_map(
                name, issues=issues, **score_kwargs,
            )

    # Deduplicate (same file + line + message from different tools)
    seen = set()
    deduped = []
    for issue in report.issues:
        key = (issue.file, issue.line, issue.message)
        if key not in seen:
            seen.add(key)
            deduped.append(issue)
    report.issues = deduped

    # Category tallies derivam de report.issues (fonte única de verdade).
    report.security_issues = sum(1 for i in report.issues if i.category == "Security")
    report.type_errors     = sum(1 for i in report.issues if i.category == "Type Error")
    report.dead_code_count = sum(1 for i in report.issues if i.category == "Dead Code")

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


def print_ruff_details(item: dict):
    data = parse_tool_json(item["stdout"])
    if not isinstance(data, list):
        print("    No structured ruff output.")
        return

    if not data:
        print("    Findings: none")
        return

    print(f"    Findings: {len(data)}")
    for entry in data:
        if not isinstance(entry, dict):
            continue
        location = entry.get("location", {})
        if not isinstance(location, dict):
            location = {}
        print(
            f"      L{location.get('row', 0):<4} "
            f"{as_str(entry.get('code'), '?'):<8} "
            f"{as_str(entry.get('message'))}"
        )


def print_prospector_details(item: dict):
    data = parse_tool_json(item["stdout"])
    if isinstance(data, dict):
        messages = data.get("messages", [])
    elif isinstance(data, list):
        messages = data
    else:
        print("    No structured prospector output.")
        return

    if not isinstance(messages, list) or not messages:
        print("    Findings: none")
        return

    print(f"    Findings: {len(messages)}")
    for entry in messages:
        if not isinstance(entry, dict):
            continue
        location = entry.get("location", {})
        if not isinstance(location, dict):
            location = {}
        source = as_str(entry.get("source"), "prospector")
        code = as_str(entry.get("code"), "?")
        print(
            f"      L{location.get('line', entry.get('line', 0)):<4} "
            f"{source}:{code:<18} "
            f"{as_str(entry.get('message'))}"
        )


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


def print_semgrep_details(item: dict):
    data = parse_tool_json(item["stdout"])
    if not isinstance(data, dict):
        print("    No structured semgrep output.")
        return

    results = data.get("results", [])
    if not isinstance(results, list) or not results:
        print("    Findings: none")
        return

    print(f"    Findings: {len(results)}")
    for result in results:
        if not isinstance(result, dict):
            continue
        start = result.get("start", {})
        if not isinstance(start, dict):
            start = {}
        extra = result.get("extra", {})
        if not isinstance(extra, dict):
            extra = {}
        print(
            f"      L{start.get('line', 0):<4} "
            f"{as_str(result.get('check_id'), 'semgrep'):<32} "
            f"{as_str(extra.get('message'))}"
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


def print_pydeps_details(item: dict):
    data = parse_tool_json(item["stdout"])
    if not isinstance(data, dict):
        print("    No structured pydeps output.")
        return

    modules = data.get("modules") or {}
    cycles = data.get("cycles") or []
    print(f"    Modules analyzed: {len(modules)}")
    if not modules:
        return

    fan_in = Counter()
    fan_out = Counter()
    edges = 0
    for name, info in modules.items():
        if not isinstance(info, dict):
            continue
        for dep in info.get("imports") or []:
            if dep in modules and dep != name:
                fan_out[name] += 1
                fan_in[dep] += 1
                edges += 1

    print(f"    Edges: {edges}")
    print(f"    Avg out-degree: {round(edges / max(len(modules), 1), 2)}")

    print(f"    Import cycles: {len(cycles)}")
    for cycle in cycles[:10]:
        print(f"      cycle ({len(cycle)}): {', '.join(cycle)}")

    if fan_out:
        top_out = fan_out.most_common(5)
        print("    Top fan-out:")
        for name, count in top_out:
            print(f"      {count:>3}  {name}")
    if fan_in:
        top_in = fan_in.most_common(5)
        print("    Top fan-in:")
        for name, count in top_in:
            print(f"      {count:>3}  {name}")


TOOL_PRINTERS: Dict[str, Tuple[str, Callable[[dict], None]]] = {
    "pylint":     ("pylint",                print_pylint_details),
    "flake8":     ("flake8",                print_flake8_details),
    "ruff":       ("ruff",                  print_ruff_details),
    "prospector": ("prospector",            print_prospector_details),
    "bandit":     ("bandit",                print_bandit_details),
    "semgrep":    ("semgrep",               print_semgrep_details),
    "pydeps":     ("pydeps",                print_pydeps_details),
    "radon-cc":   ("radon complexity",      print_radon_cc_details),
    "radon-mi":   ("radon maintainability", print_radon_mi_details),
    "radon-raw":  ("radon raw metrics",     print_radon_raw_details),
    "vulture":    ("vulture", lambda item: print_line_tool_details(item, "Dead-code findings")),
    "mypy":       ("mypy",    lambda item: print_line_tool_details(item, "Type findings")),
}


def print_tool_outputs(report: Report):
    print(f"\n  {c(f'{BOLD}{WHITE}', '🧾 TOOL DETAILS')}")
    print(f"  {c(DIM, '─' * 68)}")

    for item in report.tool_outputs:
        tool_name = tool_output_key(item["cmd"])
        entry = TOOL_PRINTERS.get(tool_name)
        if entry:
            header, detail_fn = entry
            print_tool_header(header, item)
            detail_fn(item)

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
    powered_by = "pylint + flake8 + ruff + prospector + bandit + semgrep + pydeps + radon + vulture + mypy"
    print(f"  {c(DIM, f'Powered by: {powered_by}')}")
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
        - `ruff`: derived from reported findings.
        - `prospector`: derived from reported findings.
        - `bandit`: derived from reported findings.
        - `semgrep`: derived from reported findings.
        - `vulture`: derived from reported findings.
        - `mypy`: derived from reported findings.
        - `radon`: derived from native metrics, using the average of:
          - maintainability index
          - a complexity score computed from average cyclomatic complexity

        ## Penalty Model

        For `flake8`, `ruff`, `prospector`, `bandit`, `semgrep`, `vulture`, and `mypy`, PyQuality computes:

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

        ### ruff penalties

        - `CRITICAL`: 25
        - `HIGH`: 12
        - `MEDIUM`: 5
        - `LOW`: 2
        - `INFO`: 1

        Severity mapping used by PyQuality:

        - `S*` -> `HIGH` / `Security`
        - `F*`, `B*`, `BLE*`, `PLE*`, `PLC*`, and `E9*` -> `HIGH` / `Bug`
        - `C90*` and `PLR09*` -> `MEDIUM` / `Complexity`
        - `E*`, `W*`, and `I*` -> `LOW` / `Style`
        - all other Ruff rules -> `MEDIUM` / `Code Smell`

        ### prospector penalties

        - `CRITICAL`: 25
        - `HIGH`: 12
        - `MEDIUM`: 5
        - `LOW`: 2
        - `INFO`: 1

        Severity mapping used by PyQuality:

        - `bandit` and `dodgy` messages -> `Security`
        - `mccabe` messages -> `Complexity`
        - `mypy` and `pyright` messages -> `Type Error`
        - `vulture` messages -> `Dead Code`
        - `pyflakes` and pylint `E/F` messages -> `Bug`
        - `pydocstyle`, `pycodestyle`, and pylint `C/R` messages -> convention/style smell bands

        ### bandit penalties

        - `CRITICAL`: 35
        - `HIGH`: 20
        - `MEDIUM`: 8
        - `LOW`: 3

        Severity mapping used by PyQuality:

        - Bandit `HIGH` -> PyQuality `CRITICAL`
        - Bandit `MEDIUM` -> PyQuality `HIGH`
        - Bandit `LOW` -> PyQuality `MEDIUM`

        ### semgrep penalties

        - `CRITICAL`: 35
        - `HIGH`: 18
        - `MEDIUM`: 8
        - `LOW`: 3

        Severity mapping used by PyQuality:

        - Semgrep `ERROR` -> `HIGH`
        - Semgrep `WARNING` -> `MEDIUM`
        - Semgrep `INFO` -> `LOW`
        - security findings with `impact=HIGH` and `confidence=HIGH` -> `CRITICAL`

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
        semgrep_config=args.semgrep_config,
        prospector_strictness=args.prospector_strictness,
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
              ruff       Fast Python lint aggregation
              prospector Aggregated Python static analysis
              bandit     Security vulnerability scanning
              semgrep    Pattern-based bug and security scanning
              radon      Cyclomatic complexity & maintainability
              vulture    Dead code detection
              mypy       Static type checking

            Examples:
              pyquality .                   Analyze current directory
              pyquality src/ -v             Show all issues in detail
              pyquality app.py --json       JSON output for CI pipelines
              pyquality src/ -t B           Fail if grade drops below B
              pyquality src/ --skip-mypy    Skip type checking (faster)
              pyquality src/ --prospector-strictness high
                                          Make Prospector stricter
              pyquality src/ --semgrep-config rules/semgrep.yml
                                          Override the bundled local Semgrep rules
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
    parser.add_argument("--prospector-strictness", default=os.environ.get("PYQUALITY_PROSPECTOR_STRICTNESS", "medium"),
                        choices=["verylow", "low", "medium", "high", "veryhigh"],
                        help="Prospector strictness level (default: medium)")
    parser.add_argument("--semgrep-config", default=os.environ.get("PYQUALITY_SEMGREP_CONFIG"),
                        help="Semgrep config path (default: bundled local rules)")

    args = parser.parse_args()

    if args.path is None:
        run_interactive_menu(args)
        return

    run_analysis_from_args(args)


if __name__ == "__main__":
    main()
