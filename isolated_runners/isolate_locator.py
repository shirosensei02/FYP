"""Locate vulnerable files for one package.

Reads isolated_runners/_config.json, then runs package input, vulnerability
detection, and official-patch resolution so the locator sees the same advisory
the pipeline would. It stops once the locator names the files.

  python isolated_runners/isolate_locator.py
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = Path(__file__).resolve().parent / "_config.json"
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from locator import locator_node, route_after_locator
from model_catalog import patch_evaluator_models
from og_patch_resolution import og_patch_resolution
from package_input import package_input
from prompt_variant import apply_run_config
from repo_graph import repo_graph_node, route_after_repo_graph
from vulnerability_detection import vulnerability_detection

MAX_TURNS = 48


class _Stop(Exception):
    def __init__(self, message: str, state: dict | None = None):
        self.message = message
        self.state = state or {}


def run(config: dict) -> dict:
    """Run one locator package. A failed package returns instead of exiting."""
    try:
        return _run(config)
    except _Stop as exc:
        print(exc.message, flush=True)
        return {"ok": False, "error": exc.message, "state": exc.state, "saved": None}


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    result = run(_load_config())
    if not result["ok"]:
        sys.exit(1)


def _run(config: dict) -> dict:
    state: dict = {
        "package_name": config["package_name"],
        "package_version": config["package_version"],
        "model_provider": config.get("model_provider") or "openrouter",
        "patch_scope": "single",
        "retry_count": 0,
        "errors": [],
    }
    if config.get("model_name"):
        state["model_name"] = config["model_name"]
    apply_run_config(state, config)

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

    state.update(localize(state))
    _print_final(state)
    return {"ok": True, "error": None, "state": state}


def localize(state: dict) -> dict:
    """Run repo_graph and the locator until locations are ranked or the loop stops."""
    pending = "repo_graph"
    for _turn in range(MAX_TURNS):
        if pending == "repo_graph":
            state.update(repo_graph_node(state))
            result = state.get("graph_result")
            if result:
                _print_result(result)
            pending = route_after_repo_graph(state)
            continue
        if pending == "locator":
            state.update(locator_node(state))
            request = state.get("graph_request")
            if request:
                print(
                    f"tool: {request.get('tool')} {json.dumps(request.get('arguments') or {}, ensure_ascii=False)}",
                    flush=True,
                )
            pending = route_after_locator(state)
            if pending == "generation":
                return state
            continue
        break
    return state


def _print_final(state: dict) -> None:
    locations = list(state.get("debug_locations") or [])
    files = list(state.get("localized_files") or [])
    if not files:
        files = list(dict.fromkeys(item.get("path") for item in locations if item.get("path")))
    print("\n===== locator result =====", flush=True)
    print(f"status: {state.get('locate_status')}", flush=True)
    print(f"graph: {state.get('repo_graph_summary')}", flush=True)
    print(f"cost: {state.get('run_cost')}", flush=True)
    print("files:", flush=True)
    if not files:
        print("  (none)", flush=True)
    for path in files:
        print(f"  {path}", flush=True)
    print("locations:", flush=True)
    if not locations:
        print("  (none)", flush=True)
    for index, item in enumerate(locations, start=1):
        class_name = item.get("class") or ""
        function = item.get("function") or ""
        name = f"{class_name}.{function}" if class_name else function
        line = item.get("line")
        where = f":{line}" if line else ""
        print(f"  {index}. {item.get('path')}{where} {name}".rstrip(), flush=True)


def _print_result(result: dict) -> None:
    entities = result.get("entities") or []
    ids = ", ".join(str(item.get("id")) for item in entities[:8]) or "(none)"
    print(f"result: {result.get('tool') or 'graph'} {ids}", flush=True)


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
