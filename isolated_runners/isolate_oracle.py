"""Generate and baseline-validate one security oracle.

Reads isolated_runners/_config.json, then runs package input, vulnerability
detection, and official-patch resolution. It generates an oracle and validates
it against the vulnerable package and the maintainer-fixed package, retrying
an invalid oracle within the same attempt budget as the graph.

Each invocation writes a new directory:

  isolated_runners/generated_oracles/<package>_<version>_<N>/

N starts at 1 for that package version and increments, so another model or a
later run of the same model keeps its own script.

  python isolated_runners/isolate_oracle.py
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
OUTPUT_ROOT = Path(__file__).resolve().parent / "generated_oracles"
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from model_catalog import patch_evaluator_models
from og_patch_resolution import og_patch_resolution
from oracle_generation import oracle_generation
from oracle_validation import oracle_validation
from package_input import package_input
from vulnerability_detection import vulnerability_detection


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    config = _load_config()
    state: dict = {
        "package_name": config["package_name"],
        "package_version": config["package_version"],
        "model_provider": config.get("model_provider") or "openrouter",
        "patch_scope": "single",
        "retry_count": 0,
        "errors": [],
        "run_cost": 0.0,
        "oracle_attempt_count": 0,
        "oracle_attempts": [],
    }
    if config.get("model_name"):
        state["model_name"] = config["model_name"]
    if config.get("max_oracle_attempts") is not None:
        state["max_oracle_attempts"] = int(config["max_oracle_attempts"])

    source_dir = str(config.get("source_dir") or "").strip()
    if source_dir:
        source = Path(source_dir).resolve()
        if not source.is_dir():
            sys.exit(f"ERROR: source_dir does not exist: {source}")
        state["source_dir"] = str(source)
        state["package_manifest_path"] = str(source / "package.json")
    else:
        state.update(package_input(state))
        if state.get("errors"):
            sys.exit("ERROR: package input failed:\n" + "\n".join(state["errors"]))
    print(f"source_dir: {state.get('source_dir')}", flush=True)

    state.update(vulnerability_detection(state))
    findings = list(state.get("current_vulnerabilities") or [])
    print(f"findings: {len(findings)}", flush=True)
    for error in state.get("errors") or []:
        print(f"detection: {error}", flush=True)
    vulnerability_id = str(config.get("vulnerability_id") or "").strip()
    if vulnerability_id:
        selected = _find_vulnerability(findings, vulnerability_id)
        if selected is None:
            sys.exit(f"ERROR: vulnerability not detected: {vulnerability_id}")
        findings = [selected]
        state["current_vulnerabilities"] = findings
    if not findings:
        sys.exit("ERROR: no target vulnerability detected")
    for finding in findings:
        print(f"  - {finding.get('id')} ({finding.get('severity')})", flush=True)

    state.update(og_patch_resolution(state))
    answer = state.get("answer_key") or {}
    print(
        f"resolution: {answer.get('status')} {answer.get('ghsa_id') or answer.get('cve_id') or ''}".rstrip(),
        flush=True,
    )

    while True:
        state.update(oracle_generation(state))
        candidate = state.get("oracle_candidate") or {}
        print(
            f"oracle generation: attempt {candidate.get('attempt_number')} status {candidate.get('status')}",
            flush=True,
        )
        state.update(oracle_validation(state))
        validation = state.get("oracle_validation") or {}
        vulnerable = (validation.get("vulnerable") or {}).get("status")
        fixed = (validation.get("fixed") or {}).get("status")
        print(
            f"oracle validation: {validation.get('status')} vulnerable={vulnerable} fixed={fixed}",
            flush=True,
        )
        print(f"  {validation.get('reason')}", flush=True)
        if _oracle_route(state) != "retry":
            break

    destination = _write_oracle(state)
    validation = state.get("oracle_validation") or {}
    print(f"saved: {destination}", flush=True)
    print(f"cost: {state.get('run_cost')}", flush=True)
    if validation.get("status") != "VALID":
        sys.exit(1)


def _oracle_route(state: dict) -> str:
    """Match graph.route_after_oracle_validation without compiling the graph."""
    validation = state.get("oracle_validation") or {}
    attempts = int(state.get("oracle_attempt_count") or 0)
    maximum = int(state.get("max_oracle_attempts") or 5)
    if validation.get("status") == "INVALID" and attempts < maximum:
        return "retry"
    return "continue"


def _write_oracle(state: dict) -> Path:
    """Store the final script and the baseline evidence under the next run number."""
    destination = _next_output_dir(state.get("package_name") or "package", state.get("package_version") or "unknown")
    destination.mkdir(parents=True, exist_ok=False)
    accepted = state.get("accepted_oracle") or {}
    candidate = state.get("oracle_candidate") or {}
    chosen = accepted or candidate
    source = str(chosen.get("source") or "")
    if source:
        (destination / "oracle.js").write_text(source, encoding="utf-8", newline="\n")
    for attempt in state.get("oracle_attempts") or []:
        generation = attempt.get("generation") or {}
        attempt_source = str(generation.get("source") or "")
        number = attempt.get("attempt_number")
        if attempt_source and number:
            (destination / f"attempt-{number}.js").write_text(attempt_source, encoding="utf-8", newline="\n")
    validation = state.get("oracle_validation") or {}
    record = {
        "package_name": state.get("package_name"),
        "package_version": state.get("package_version"),
        "model_provider": state.get("model_provider"),
        "model_name": chosen.get("model_used") or state.get("model_name"),
        "vulnerability_ids": [item.get("id") for item in (state.get("current_vulnerabilities") or [])],
        "run_index": int(destination.name.rsplit("_", 1)[-1]),
        "run_cost": state.get("run_cost"),
        "oracle_attempt_count": state.get("oracle_attempt_count"),
        "validation_status": validation.get("status"),
        "validation_reason": validation.get("reason"),
        "guidance": validation.get("guidance") or [],
        "vulnerable": _slim_execution(validation.get("vulnerable")),
        "fixed": _slim_execution(validation.get("fixed")),
        "oracle": {
            "status": "accepted" if accepted else chosen.get("status"),
            "attempt_number": chosen.get("attempt_number"),
            "explanation": chosen.get("explanation"),
            "requirements": chosen.get("requirements") or [],
            "timeout_seconds": chosen.get("timeout_seconds"),
            "model_used": chosen.get("model_used"),
        },
        "attempts": [_slim_attempt(attempt) for attempt in (state.get("oracle_attempts") or [])],
    }
    (destination / "result.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=False),
        encoding="utf-8",
        newline="\n",
    )
    return destination


def _slim_attempt(attempt: dict) -> dict:
    generation = attempt.get("generation") or {}
    validation = attempt.get("validation") or {}
    return {
        "attempt_number": attempt.get("attempt_number"),
        "generation_status": generation.get("status"),
        "explanation": generation.get("explanation"),
        "requirements": generation.get("requirements") or [],
        "model_used": generation.get("model_used"),
        "validation_status": validation.get("status"),
        "validation_reason": validation.get("reason"),
        "vulnerable_status": (validation.get("vulnerable") or {}).get("status"),
        "fixed_status": (validation.get("fixed") or {}).get("status"),
    }


def _slim_execution(execution: dict | None) -> dict | None:
    if not isinstance(execution, dict):
        return None
    keys = (
        "status",
        "operation_completed",
        "exploit_succeeded",
        "evidence",
        "exit_code",
        "failure_kind",
        "timed_out",
    )
    return {key: execution.get(key) for key in keys if key in execution}


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
