"""Generate one patch and validate it against a frozen oracle.

Reads isolated_runners/_config.json, then runs package input, vulnerability
detection, and official-patch resolution. The answer key names the vulnerable
function. The function body is loaded from the package graph, which is the
source slice patch generation normally receives from the locator. The patch is
then checked against the locked oracle for that package. Package tests are not
run. A passing oracle stops the loop. An exploit that still succeeds, a
broken operation, a generation failure,
or an apply failure consumes one attempt.

Each invocation writes a new directory:

  isolated_runners/generated_patches/<package>_<version>_<N>/

  python isolated_runners/isolate_patch_gen.py
"""

from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = Path(__file__).resolve().parent / "_config.json"
ANSWER_KEY_PATH = Path(__file__).resolve().parent / "locator_answer_key.json"
OUTPUT_ROOT = Path(__file__).resolve().parent / "generated_patches"
LOCKED_ROOT = Path(__file__).resolve().parent / "locked_oracles"
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from failure_context import record_failure
from locator import _clean_locations, _locations_with_bodies
from locator_answer import load_answer_key
from model_catalog import patch_evaluator_models
from og_patch_resolution import og_patch_resolution
from oracle_validation import generated_patch_oracle_validation
from package_input import package_input
from patch_application import apply_patch
from patch_generation import MAX_PATCH_GRAPH_FETCHES, patch_generation
from patch_validation import record_locked_oracle_failure
from prompt_variant import apply_run_config
from repo_graph import repo_graph_node
from vulnerability_detection import vulnerability_detection


class _Stop(Exception):
    def __init__(self, message: str, state: dict | None = None):
        self.message = message
        self.state = state or {}


def run(config: dict) -> dict:
    """Run one patch package. A failed package returns instead of exiting."""
    try:
        return _run(config)
    except _Stop as exc:
        print(exc.message, flush=True)
        return {"ok": False, "error": exc.message, "state": exc.state, "success_loop": None, "saved": None}


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    result = run(_load_config())
    if not result["ok"]:
        sys.exit(1)


def apply_answer_key_locations(state: dict, answer_key: dict | None = None) -> dict:
    """Name the vulnerable functions from the answer key and load their bodies.

    Patch generation uses ``debug_locations`` only when each entry has a body.
    The key stores the path, function, and lines. The body is read from the
    package graph, which is the same handoff the locator produces.
    """
    key = load_answer_key(ANSWER_KEY_PATH) if answer_key is None else answer_key
    package = str(state.get("package_name") or "")
    version = str(state.get("package_version") or "")
    expected = key.get((package, version)) or []
    if not expected:
        raise FileNotFoundError(f"no answer-key locations for {package}@{version}")
    ranked = _clean_locations(expected)
    locations = _locations_with_bodies(state, ranked)
    found = {item.get("id") for item in locations}
    missing = [str(item.get("id") or item.get("path") or "") for item in ranked if item.get("id") not in found]
    if not locations:
        detail = ", ".join(item for item in missing if item) or "none"
        raise FileNotFoundError(f"answer-key locations have no function body: {detail}")
    return {
        "debug_locations": locations,
        "localized_files": list(dict.fromkeys(item["path"] for item in locations if item.get("path"))),
        "unresolved_locations": [item for item in missing if item],
    }


def load_locked_oracle(package: str, version: str) -> dict:
    """Return the accepted oracle copied for this package version."""
    directory = LOCKED_ROOT / f"{_safe_component(package)}_{_safe_component(version)}"
    manifest_path = directory / "oracle.json"
    script_path = directory / "oracle.js"
    if not manifest_path.is_file() or not script_path.is_file():
        raise FileNotFoundError(f"no locked oracle for {package}@{version}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source = script_path.read_text(encoding="utf-8")
    if not isinstance(manifest, dict) or not source.strip():
        raise FileNotFoundError(f"no locked oracle for {package}@{version}")
    requirements = manifest.get("requirements") or []
    if not isinstance(requirements, list):
        requirements = []
    return {
        "status": "accepted",
        "source": source,
        "attempt_number": manifest.get("attempt_number"),
        "timeout_seconds": manifest.get("timeout_seconds") or 30,
        "requirements": requirements,
        "source_run": manifest.get("source_run"),
        "vulnerability_ids": list(manifest.get("vulnerability_ids") or []),
    }


def _run(config: dict) -> dict:
    state: dict = {
        "package_name": config["package_name"],
        "package_version": config["package_version"],
        "model_provider": config.get("model_provider") or "openrouter",
        "patch_scope": "single",
        "retry_count": 0,
        "errors": [],
        "run_cost": 0.0,
    }
    if config.get("model_name"):
        state["model_name"] = config["model_name"]
    apply_run_config(state, config)
    try:
        oracle = load_locked_oracle(state["package_name"], state["package_version"])
    except FileNotFoundError as exc:
        raise _Stop(f"ERROR: {exc}", state) from exc
    state["accepted_oracle"] = oracle
    print(
        f"locked oracle: {oracle.get('source_run')} attempt {oracle.get('attempt_number')}",
        flush=True,
    )

    source_dir = str(config.get("source_dir") or "").strip()
    if source_dir:
        source = Path(source_dir).resolve()
        if not source.is_dir():
            raise _Stop(f"ERROR: source_dir does not exist: {source}", state)
        state["source_dir"] = str(source)
        state["package_manifest_path"] = str(source / "package.json")
    else:
        state.update(package_input(state))
        if state.get("errors"):
            raise _Stop("ERROR: package input failed:\n" + "\n".join(state["errors"]), state)
    print(f"source_dir: {state.get('source_dir')}", flush=True)
    try:
        state.update(apply_answer_key_locations(state))
    except FileNotFoundError as exc:
        raise _Stop(f"ERROR: {exc}", state) from exc
    print(f"locations: {len(state.get('debug_locations') or [])}", flush=True)
    for item in state.get("debug_locations") or []:
        line = item.get("line")
        where = f":{line}" if line else ""
        print(f"  {item.get('path')}{where} {item.get('function') or ''}".rstrip(), flush=True)
    unresolved = state.get("unresolved_locations") or []
    if unresolved:
        print(f"unresolved: {', '.join(unresolved)}", flush=True)

    state.update(vulnerability_detection(state))
    findings = list(state.get("current_vulnerabilities") or [])
    print(f"findings: {len(findings)}", flush=True)
    for error in state.get("errors") or []:
        print(f"detection: {error}", flush=True)
    vulnerability_id = str(config.get("vulnerability_id") or "").strip()
    if vulnerability_id:
        selected = _find_vulnerability(findings, vulnerability_id)
        if selected is None:
            raise _Stop(f"ERROR: vulnerability not detected: {vulnerability_id}", state)
        findings = [selected]
        state["current_vulnerabilities"] = findings
    if not findings:
        raise _Stop("ERROR: no target vulnerability detected", state)
    for finding in findings:
        print(f"  - {finding.get('id')} ({finding.get('severity')})", flush=True)

    state.update(og_patch_resolution(state))
    answer = state.get("answer_key") or {}
    print(
        f"resolution: {answer.get('status')} {answer.get('ghsa_id') or answer.get('cve_id') or ''}".rstrip(),
        flush=True,
    )

    maximum = _attempt_limit(config)
    attempts: list[dict] = []
    success_loop = None
    for attempt in range(1, maximum + 1):
        state["retry_count"] = attempt - 1
        state["generated_patch_oracle_validation"] = None
        state["patch_applied"] = None
        _generate(state)
        diff = str((state.get("current_patch") or {}).get("diff") or "")
        generated = state.get("generation_status") == "generated" and bool(diff.strip())
        print(
            f"patch generation: attempt {attempt} status {state.get('generation_status')}",
            flush=True,
        )
        if not generated:
            reason = state.get("generation_error") or "Patch generation failed."
            print(f"  {reason}", flush=True)
            record_failure(state, reason, stage="generation")
            attempts.append(_attempt_record(attempt, state, diff="", oracle_status=None, reason=reason))
            continue

        state.update(apply_patch(state))
        applied = state.get("patch_applied") is True
        print(f"patch apply: {'applied' if applied else 'failed'}", flush=True)
        if not applied:
            reason = "Patch could not be applied to the source."
            print(f"  {reason}", flush=True)
            record_failure(state, reason, stage="application", candidate=diff)
            attempts.append(_attempt_record(attempt, state, diff=diff, oracle_status=None, reason=reason))
            continue

        state.update(generated_patch_oracle_validation(state))
        validation = state.get("generated_patch_oracle_validation") or {}
        status = validation.get("status")
        reason = validation.get("reason") or "Locked oracle did not pass."
        execution = (validation.get("execution") or {}).get("status")
        print(f"oracle validation: {status} execution={execution}", flush=True)
        print(f"  {reason}", flush=True)
        attempts.append(_attempt_record(attempt, state, diff=diff, oracle_status=status, reason=reason))
        if status == "SECURITY_PASS":
            success_loop = attempt
            break
        if status in {"SECURITY_FAIL", "REGRESSION"}:
            state.update(record_locked_oracle_failure(state))
            continue
        record_failure(state, reason, stage="security_oracle")

    destination = _write_patch(state, attempts, success_loop)
    print(f"saved: {destination}", flush=True)
    print(f"cost: {state.get('run_cost')}", flush=True)
    passed = success_loop is not None
    last = attempts[-1] if attempts else {}
    return {
        "ok": passed,
        "error": None if passed else last.get("reason"),
        "state": state,
        "success_loop": success_loop,
        "saved": str(destination),
    }


def _generate(state: dict) -> None:
    """Generate a patch, serving graph-tool requests within the existing fetch limit."""
    state["graph_request"] = None
    for _turn in range(MAX_PATCH_GRAPH_FETCHES + 2):
        state.update(patch_generation(state))
        if state.get("generation_status") == "failed":
            state["graph_request"] = None
            return
        request = state.get("graph_request")
        if not isinstance(request, dict):
            return
        print(
            f"tool: {request.get('tool')} {json.dumps(request.get('arguments') or {}, ensure_ascii=False)}",
            flush=True,
        )
        state.update(repo_graph_node(state))
    state["generation_status"] = "failed"
    state["generation_error"] = "patch_generation: graph tool loop did not finish"
    state["current_patch"] = None
    state["graph_request"] = None


def _attempt_limit(config: dict) -> int:
    raw = config.get("max_patch_attempts")
    if raw is None:
        raw = config.get("max_loop") or 10
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = 10
    return limit if limit >= 1 else 1


def _attempt_record(attempt: int, state: dict, *, diff: str, oracle_status: str | None, reason: str) -> dict:
    validation = state.get("generated_patch_oracle_validation") or {}
    execution = validation.get("execution") if isinstance(validation.get("execution"), dict) else {}
    return {
        "attempt_number": attempt,
        "generation_status": state.get("generation_status"),
        "patch_applied": state.get("patch_applied") is True,
        "oracle_status": oracle_status,
        "reason": reason,
        "execution_status": execution.get("status"),
        "evidence": execution.get("evidence"),
        "diff": diff,
    }


def _write_patch(state: dict, attempts: list[dict], success_loop: int | None) -> Path:
    destination = _next_output_dir(state.get("package_name") or "package", state.get("package_version") or "unknown")
    destination.mkdir(parents=True, exist_ok=False)
    chosen = next((item for item in attempts if item.get("attempt_number") == success_loop), None)
    if chosen is None:
        chosen = next((item for item in reversed(attempts) if item.get("diff")), None)
    diff = str((chosen or {}).get("diff") or "")
    if diff:
        (destination / "patch.diff").write_text(diff, encoding="utf-8", newline="\n")
    for attempt in attempts:
        attempt_diff = str(attempt.get("diff") or "")
        number = attempt.get("attempt_number")
        if attempt_diff and number:
            (destination / f"attempt-{number}.diff").write_text(attempt_diff, encoding="utf-8", newline="\n")
    oracle = state.get("accepted_oracle") or {}
    last = attempts[-1] if attempts else {}
    record = {
        "package_name": state.get("package_name"),
        "package_version": state.get("package_version"),
        "model_provider": state.get("model_provider"),
        "model_name": state.get("generation_model_used") or state.get("model_name"),
        "vulnerability_ids": [item.get("id") for item in (state.get("current_vulnerabilities") or [])],
        "run_index": int(destination.name.rsplit("_", 1)[-1]),
        "run_cost": state.get("run_cost"),
        "patch_attempt_count": len(attempts),
        "success_loop": success_loop,
        "validation_status": "SECURITY_PASS" if success_loop else (last.get("oracle_status") or "FAILED"),
        "validation_reason": None if success_loop else last.get("reason"),
        "locked_oracle": {
            "source_run": oracle.get("source_run"),
            "attempt_number": oracle.get("attempt_number"),
        },
        "attempts": [_slim_attempt(attempt) for attempt in attempts],
    }
    if success_loop:
        record["validation_reason"] = next(
            (item.get("reason") for item in attempts if item.get("attempt_number") == success_loop),
            None,
        )
    (destination / "result.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=False),
        encoding="utf-8",
        newline="\n",
    )
    return destination


def _slim_attempt(attempt: dict) -> dict:
    return {
        "attempt_number": attempt.get("attempt_number"),
        "generation_status": attempt.get("generation_status"),
        "patch_applied": attempt.get("patch_applied"),
        "oracle_status": attempt.get("oracle_status"),
        "reason": attempt.get("reason"),
        "execution_status": attempt.get("execution_status"),
        "evidence": attempt.get("evidence"),
    }


def _next_output_dir(package: str, version: str) -> Path:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    prefix = f"{_safe_component(package)}_{_safe_component(version)}_"
    highest = 0
    for child in OUTPUT_ROOT.iterdir():
        if not child.is_dir() or not child.name.startswith(prefix):
            continue
        suffix = child.name[len(prefix):]
        if suffix.isdigit():
            highest = max(highest, int(suffix))
    return OUTPUT_ROOT / f"{prefix}{highest + 1}"


def _safe_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value).strip()).strip("._")
    return cleaned or "unknown"


def _load_config() -> dict:
    if not CONFIG_PATH.is_file():
        sys.exit(f"ERROR: missing config: {CONFIG_PATH}")
    try:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.exit(f"ERROR: {CONFIG_PATH.name} is not valid JSON: {exc}")
    if not isinstance(config, dict):
        sys.exit(f"ERROR: {CONFIG_PATH.name} must be a JSON object")
    if not str(config.get("package_name") or "").strip() or not str(config.get("package_version") or "").strip():
        sys.exit("ERROR: _config.json needs package_name and package_version")
    model_name = str(config.get("model_name") or "").strip()
    if model_name and model_name not in patch_evaluator_models():
        sys.exit(f"ERROR: model_name must be one of: {', '.join(patch_evaluator_models())}")
    config["package_name"] = str(config["package_name"]).strip()
    config["package_version"] = str(config["package_version"]).strip()
    config["model_name"] = model_name
    return config


def _find_vulnerability(findings: list[dict], requested_id: str) -> dict | None:
    wanted = requested_id.strip().casefold()
    for finding in findings:
        identifiers = [finding.get("id"), *(finding.get("aliases") or [])]
        if wanted in {str(item).casefold() for item in identifiers if item}:
            return finding
    return None


if __name__ == "__main__":
    main()
