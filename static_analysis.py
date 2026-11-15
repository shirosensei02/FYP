"""
Static security analysis of generated patches (Semgrep).

Runs Semgrep on both the baseline (original vulnerable) source and the patched
source, then computes the *differential* findings: only new issues introduced
by the patch are flagged. Pre-existing findings in the baseline are ignored.

Called directly inside ``patch_application.apply_patch`` right after the patched
files are written to disk, and the result is saved under ``state["static_analysis"]``.

GraphState keys consumed
------------------------
- ``source_dir``         : str  - original unmodified package source
- ``patched_source_dir`` : str  - workspace with the generated patch applied
- ``patch_applied``      : bool - True when the patch was written successfully
- ``current_patch``      : PatchAttempt - used to extract changed file paths

GraphState keys produced
------------------------
- ``static_analysis``    : dict - full results (see _result())
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

from state import GraphState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SEMGREP_TIMEOUT = 120  # seconds per scan
SCANS_ROOT = Path(__file__).resolve().parent / ".workspace" / "static_analysis"

# Semgrep rulesets to use.  "p/javascript" covers generic JS/TS security
# rules; "p/nodejsscan" adds Node-specific checks (command injection, path
# traversal, prototype pollution, etc.).
SEMGREP_RULESETS = [
    "p/javascript",
    "p/nodejsscan",
]

# Severity levels that should block the patch.
BLOCKING_SEVERITIES = {"ERROR", "WARNING"}

# Source file extensions to scan.
SOURCE_SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx", ".cts", ".mts"}

# Directories to skip when targeting changed files.
SKIP_DIRS = {"node_modules", ".git", "__pycache__"}


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------

def _result(
    *,
    status: str,
    baseline_count: int = 0,
    patched_count: int = 0,
    new_findings: list[dict[str, Any]] | None = None,
    resolved_findings: list[dict[str, Any]] | None = None,
    scanned_files: list[str] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "baseline_finding_count": baseline_count,
        "patched_finding_count": patched_count,
        "new_findings": new_findings or [],
        "new_finding_count": len(new_findings or []),
        "resolved_findings": resolved_findings or [],
        "scanned_files": scanned_files or [],
        "error": error,
    }


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def _changed_files_from_patch(patch: dict[str, Any] | None) -> list[str]:
    """Extract the list of file paths touched by the patch."""
    if not patch:
        return []
    diff_raw = patch.get("diff", "")

    # Format 1: file-map JSON
    try:
        file_map = json.loads(diff_raw)
        if isinstance(file_map, dict):
            return list(file_map.keys())
    except (json.JSONDecodeError, TypeError):
        pass

    # Format 2: unified diff — extract paths from --- a/path and +++ b/path
    paths = set()
    for match in re.finditer(r"^(?:---|\+\+\+) [ab]/(.+)$", diff_raw, re.MULTILINE):
        path = match.group(1).strip()
        if path and path != "/dev/null":
            paths.add(path)
    return sorted(paths)


def _is_source_file(path: str) -> bool:
    """Return True if the path looks like a JS/TS source file."""
    return Path(path).suffix.lower() in SOURCE_SUFFIXES


# ---------------------------------------------------------------------------
# Semgrep runner
# ---------------------------------------------------------------------------

def _find_semgrep() -> str | None:
    """Locate the semgrep executable on PATH or in the active/local virtualenv."""
    import sys
    found = shutil.which("semgrep")
    if found:
        return found
    bin_dir = "Scripts" if os.name == "nt" else "bin"
    exe_name = "semgrep.exe" if os.name == "nt" else "semgrep"
    for base in [Path(sys.prefix), Path(__file__).resolve().parent / ".venv"]:
        candidate = base / bin_dir / exe_name
        if candidate.is_file():
            return str(candidate)
    return None


def _run_semgrep(
    target_dir: Path,
    target_files: list[str] | None = None,
    output_path: Path | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Run Semgrep and return ``(findings, error_or_none)``.

    Parameters
    ----------
    target_dir
        Root directory of the package source to scan.
    target_files
        If given, only scan these relative paths (the changed files).
        If None, scan the entire directory.
    output_path
        If given, write the raw Semgrep JSON output here for debugging.

    Returns
    -------
    findings : list[dict]
        Each finding has ``rule_id``, ``path``, ``start_line``, ``end_line``,
        ``message``, ``severity``, and ``metadata``.
    error : str | None
        Error message if the scan failed, else None.
    """
    import subprocess

    semgrep_path = _find_semgrep()
    if not semgrep_path:
        return [], "semgrep is not installed or not on PATH"

    # Build the command
    cmd = [
        semgrep_path,
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        "--timeout", str(SEMGREP_TIMEOUT),
    ]
    for ruleset in SEMGREP_RULESETS:
        cmd.extend(["--config", ruleset])

    if target_files:
        # Only scan the specific changed files
        absolute_targets = []
        for rel_path in target_files:
            full_path = target_dir / rel_path
            if full_path.is_file() and _is_source_file(rel_path):
                absolute_targets.append(str(full_path))
        if not absolute_targets:
            return [], None  # No scannable source files changed
        cmd.extend(absolute_targets)
    else:
        cmd.append(str(target_dir))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT + 30,
            cwd=str(target_dir),
        )
    except subprocess.TimeoutExpired:
        return [], "semgrep timed out"
    except FileNotFoundError:
        return [], "semgrep executable not found"

    # Semgrep exit codes: 0 = no findings, 1 = findings found, other = error.
    # Both 0 and 1 produce valid JSON output.
    raw_output = proc.stdout or ""
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(raw_output, encoding="utf-8")

    if proc.returncode not in (0, 1):
        err_msg = (proc.stderr or "").strip()[:500]
        return [], f"semgrep exited with code {proc.returncode}: {err_msg}"

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return [], "failed to parse semgrep JSON output"

    findings = []
    for result in data.get("results", []):
        finding = {
            "rule_id": result.get("check_id", ""),
            "path": str(
                Path(result.get("path", "")).relative_to(target_dir)
                if result.get("path")
                else ""
            ),
            "start_line": result.get("start", {}).get("line"),
            "end_line": result.get("end", {}).get("line"),
            "message": result.get("extra", {}).get("message", ""),
            "severity": result.get("extra", {}).get("severity", "WARNING"),
            "metadata": result.get("extra", {}).get("metadata", {}),
        }
        findings.append(finding)

    return findings, None


# ---------------------------------------------------------------------------
# Differential logic
# ---------------------------------------------------------------------------

def _finding_key(finding: dict[str, Any]) -> str:
    """Stable identity for a finding, independent of exact line numbers.

    Two findings match if they are the same rule on the same file.  Line
    numbers can shift when the patch adds/removes lines, so we don't include
    them in the key.
    """
    return f"{finding.get('rule_id', '')}::{finding.get('path', '')}"


def _diff_findings(
    baseline: list[dict[str, Any]],
    patched: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (new_findings, resolved_findings).

    ``new_findings``      = in patched but NOT in baseline  (patch introduced)
    ``resolved_findings``  = in baseline but NOT in patched  (patch fixed)
    """
    baseline_keys = {_finding_key(f) for f in baseline}
    patched_keys = {_finding_key(f) for f in patched}

    new_keys = patched_keys - baseline_keys
    resolved_keys = baseline_keys - patched_keys

    new_findings = [f for f in patched if _finding_key(f) in new_keys]
    resolved_findings = [f for f in baseline if _finding_key(f) in resolved_keys]
    return new_findings, resolved_findings


# ---------------------------------------------------------------------------
# Public LangGraph node
# ---------------------------------------------------------------------------

def static_analysis(state: GraphState) -> dict[str, Any]:
    """Run differential static security analysis on the generated patch.

    Scans both the original baseline source and the patched source with
    Semgrep, then reports only *new* findings introduced by the patch.

    Returns a ``static_analysis`` dict in the state with status:
    - ``"pass"``     : no new security findings introduced
    - ``"fail"``     : new security findings detected
    - ``"skipped"``  : preconditions not met (no patch, missing dirs)
    - ``"error"``    : tool failure (semgrep not installed, timeout, etc.)
    """
    # ── Precondition checks ───────────────────────────────────────────
    if not state.get("patch_applied"):
        logger.info("static_analysis: skipped — patch was not applied")
        return {"static_analysis": _result(status="skipped", error="patch was not applied")}

    source_dir = state.get("source_dir")
    patched_dir_value = state.get("patched_source_dir")
    if not source_dir or not patched_dir_value:
        logger.info("static_analysis: skipped — missing source or patched dir")
        return {"static_analysis": _result(status="skipped", error="missing source_dir or patched_source_dir")}

    source_path = Path(source_dir)
    patched_path = Path(patched_dir_value)
    if not source_path.is_dir() or not patched_path.is_dir():
        logger.info("static_analysis: skipped — directory not found")
        return {"static_analysis": _result(status="skipped", error="source or patched directory does not exist")}

    # ── Identify changed files ────────────────────────────────────────
    changed_files = _changed_files_from_patch(state.get("current_patch"))
    source_changed = [f for f in changed_files if _is_source_file(f)]

    if not source_changed:
        logger.info("static_analysis: pass — no JS/TS source files were changed")
        return {"static_analysis": _result(status="pass", scanned_files=changed_files)}

    logger.info(
        "static_analysis: scanning %d changed source files: %s",
        len(source_changed),
        source_changed,
    )

    # ── Set up output directory ───────────────────────────────────────
    package_name = state.get("package_name", "unknown")
    attempt_id = (state.get("current_patch") or {}).get("attempt_id", "attempt")
    scan_dir = SCANS_ROOT / _safe_segment(package_name) / _safe_segment(attempt_id)
    scan_dir.mkdir(parents=True, exist_ok=True)

    # ── Scan baseline (original vulnerable source) ────────────────────
    print("\n" + "-" * 60, flush=True)
    print("  >> Static Analysis: scanning BASELINE source", flush=True)
    print("-" * 60, flush=True)

    baseline_findings, baseline_error = _run_semgrep(
        source_path,
        target_files=source_changed,
        output_path=scan_dir / "semgrep_baseline.json",
    )
    if baseline_error:
        logger.warning("static_analysis: baseline scan error: %s", baseline_error)
        return {"static_analysis": _result(status="error", error=f"baseline scan failed: {baseline_error}")}

    print(f"    Baseline findings: {len(baseline_findings)}", flush=True)

    # ── Scan patched source ───────────────────────────────────────────
    print("\n" + "-" * 60, flush=True)
    print("  >> Static Analysis: scanning PATCHED source", flush=True)
    print("-" * 60, flush=True)

    patched_findings, patched_error = _run_semgrep(
        patched_path,
        target_files=source_changed,
        output_path=scan_dir / "semgrep_patched.json",
    )
    if patched_error:
        logger.warning("static_analysis: patched scan error: %s", patched_error)
        return {"static_analysis": _result(status="error", error=f"patched scan failed: {patched_error}")}

    print(f"    Patched findings: {len(patched_findings)}", flush=True)

    # ── Differential analysis ─────────────────────────────────────────
    new_findings, resolved_findings = _diff_findings(baseline_findings, patched_findings)

    # Filter to blocking severities
    blocking = [
        f for f in new_findings
        if f.get("severity", "").upper() in BLOCKING_SEVERITIES
    ]

    status = "fail" if blocking else "pass"

    print("\n" + "-" * 60, flush=True)
    print("  >> Static Analysis: RESULTS", flush=True)
    print("-" * 60, flush=True)
    print(f"    New findings (blocking) : {len(blocking)}", flush=True)
    print(f"    New findings (total)    : {len(new_findings)}", flush=True)
    print(f"    Resolved findings       : {len(resolved_findings)}", flush=True)
    print(f"    Status                  : {status.upper()}", flush=True)

    for finding in blocking:
        print(
            f"    ⚠ {finding['rule_id']}  {finding['path']}:{finding.get('start_line', '?')}"
            f"  — {finding.get('message', '')[:120]}",
            flush=True,
        )

    logger.info(
        "static_analysis: %s — %d new blocking findings, %d resolved, scanned %s",
        status, len(blocking), len(resolved_findings), source_changed,
    )

    result = _result(
        status=status,
        baseline_count=len(baseline_findings),
        patched_count=len(patched_findings),
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        scanned_files=source_changed,
    )

    return {"static_analysis": result}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_segment(name: str) -> str:
    """Sanitise a string for use as a directory name."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name or "unknown")[:80]
