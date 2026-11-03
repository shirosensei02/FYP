"""Run official patch resolution, the symbol index, and the debugger loop.

Package download and vulnerability detection run only to supply a source tree
and a GHSA. Patch generation, Docker, and validation are not called.

Example:
  python temp.py --package-name semver --package-version 7.5.1 --model-provider openrouter --model-name anthropic/claude-sonnet-5
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))
load_dotenv(Path(__file__).resolve().parent / ".env")

from debugger import (
    MAX_DEBUG_ROUNDS,
    build_messages,
    debugger_node,
    route_after_debugger,
    route_after_index,
)
from model_catalog import patch_evaluator_models
from og_patch_resolution import (
    GITHUB_API,
    _GHSA_RE,
    _github_get,
    advisory_bug_statement,
    og_patch_resolution,
)
from package_input import package_input
from symbol_index import index_node
from vulnerability_detection import (
    SCANS_ROOT,
    _matches_target,
    _prepare_npm_lockfile_project,
    _run_npm_audit,
    _safe_segment,
    _tool_env,
    vulnerability_detection,
)

_RANGE_CONSTRAINT = re.compile(r"(<=|>=|<|>|=)\s*([0-9][0-9A-Za-z.\-]*)")


def main() -> None:
    args = _parse_args()
    state: dict = {
        "package_name": args.package_name,
        "package_version": args.package_version,
        "model_provider": args.model_provider,
        "patch_scope": "single",
        "retry_count": 0,
        "errors": [],
    }
    if args.model_name:
        state["model_name"] = args.model_name

    if args.source_dir:
        source = Path(args.source_dir).resolve()
        if not source.is_dir():
            sys.exit(f"ERROR: --source-dir does not exist: {source}")
        state["source_dir"] = str(source)
        state["package_manifest_path"] = str(source / "package.json")
        print(f"source_dir: {source}")
    else:
        state.update(package_input(state))
        if state.get("errors"):
            sys.exit("ERROR: package input failed:\n" + "\n".join(state["errors"]))
        print(f"source_dir: {state.get('source_dir')}")

    state.update(vulnerability_detection(state))
    findings = state.get("current_vulnerabilities") or []
    print(f"findings: {len(findings)}")
    for error in state.get("errors") or []:
        print(f"detection: {error}")
    if not findings:
        print("scanner found no target vulnerability; checking npm audit")
        findings = _npm_audit_findings(args.package_name, args.package_version)
        print(f"npm findings: {len(findings)}")
    if not findings:
        print("checking GitHub advisories")
        findings = _github_findings(args.package_name, args.package_version)
        print(f"github findings: {len(findings)}")
    if findings and not state.get("current_vulnerabilities"):
        state["current_vulnerabilities"] = findings
        state["target_vulnerability_found"] = True
    for finding in findings:
        print(f"  - {finding.get('id')} ({finding.get('severity')})")
    if not findings:
        sys.exit("ERROR: no target vulnerability detected")
    if args.vulnerability_id:
        selected = _find_vulnerability(findings, args.vulnerability_id)
        if selected is None:
            sys.exit(f"ERROR: vulnerability not detected: {args.vulnerability_id}")
        state["current_vulnerabilities"] = [selected]
        print(f"selected: {selected.get('id')}")

    state.update(og_patch_resolution(state))
    answer = state.get("answer_key") or {}
    print(f"resolution: {answer.get('status')} {answer.get('ghsa_id') or answer.get('cve_id')}")
    print(f"summary: {answer.get('summary')}")

    prompt_tokens = 0
    completion_tokens = 0
    while True:
        state.update(index_node(state))
        print(
            f"index: status={state.get('debug_status')} "
            f"bodies={len(state.get('debug_in_prompt') or [])} "
            f"loads={state.get('debug_body_loads')}"
        )
        if route_after_index(state) == "generation":
            break
        messages = build_messages(state)
        prompt_chars = sum(len(message.get("content") or "") for message in messages)
        print(f"prompt chars: {prompt_chars}")
        for label, message in zip(("system", "advisory", "bodies"), messages):
            print(f"  {label} chars: {len(message.get('content') or '')}")
        sent_actions = len(state.get("debug_actions") or [])
        state.update(debugger_node(state))
        sent = len(state.get("debug_actions") or []) > sent_actions
        action = (state.get("debug_actions") or [{}])[-1] if sent else {}
        usage = (state.get("debug_usage") or {}) if sent else {}
        print(
            f"debugger: status={state.get('debug_status')} "
            f"round={state.get('debug_rounds')}/{MAX_DEBUG_ROUNDS} "
            f"action={action.get('action') or 'not_sent'}"
        )
        print(f"requested: {_name_list(action.get('request'))}")
        print(f"dropped: {_name_list(action.get('drop'))}")
        if action.get("reason"):
            print(f"reason: {action.get('reason')}")
        if sent:
            prompt_tokens += int(usage.get("prompt_tokens") or 0)
            completion_tokens += int(usage.get("completion_tokens") or 0)
            print(
                "usage: "
                f"prompt_tokens={usage.get('prompt_tokens')} "
                f"completion_tokens={usage.get('completion_tokens')} "
                f"total_tokens={usage.get('total_tokens')} "
                f"cost={usage.get('cost')}"
            )
        if route_after_debugger(state) == "generation":
            break

    prompt = build_messages(state)[1]["content"]
    print("\n===== DEBUGGER PROMPT =====")
    print(prompt)
    print("\n===== FINAL DEBUGGER OUTPUT =====")
    print(f"status: {state.get('debug_status')}")
    if state.get("debug_feedback"):
        print(f"feedback: {state.get('debug_feedback')}")
    print(f"rounds: {state.get('debug_rounds')}/{MAX_DEBUG_ROUNDS}")
    print(f"cost: {state.get('run_cost')}")
    print(f"tokens: prompt={prompt_tokens} completion={completion_tokens} total={prompt_tokens + completion_tokens}")
    print("actions:")
    print(json.dumps(state.get("debug_actions") or [], indent=2))
    print("locations:")
    for item in state.get("debug_locations") or []:
        print(f"\n--- {item.get('path')} {item.get('function')} ---")
        print(f"reason: {item.get('reason') or '(none)'}")
        print(item.get("body") or "")


def _npm_audit_findings(package_name: str, package_version: str) -> list[dict]:
    """npm audit findings for this package when Syft and Grype are unavailable."""
    scan_dir = SCANS_ROOT / _safe_segment(package_name) / _safe_segment(package_version)
    scan_dir.mkdir(parents=True, exist_ok=True)
    project_dir, _, error = _prepare_npm_lockfile_project(package_name, package_version, scan_dir, _tool_env())
    if error or project_dir is None:
        print(f"npm audit lookup: {error or 'no lockfile project'}")
        return []
    vulnerabilities, _, audit_error = _run_npm_audit(
        package_name, package_version, project_dir, scan_dir, _tool_env()
    )
    findings = _matches_target(vulnerabilities, package_name)
    if audit_error and not findings:
        print(f"npm audit lookup: {audit_error}")
        return []
    for finding in findings:
        url = str(finding.get("advisory_url") or "")
        match = _GHSA_RE.search(url)
        if match and not str(finding.get("id") or "").upper().startswith("GHSA-"):
            ghsa_id = "GHSA-" + match.group(0).split("-", 1)[1].lower()
            aliases = [str(finding.get("id"))] if finding.get("id") else []
            aliases.extend(str(alias) for alias in finding.get("aliases") or [])
            finding["aliases"] = aliases
            finding["id"] = ghsa_id
    return findings


def _github_findings(package_name: str, package_version: str) -> list[dict]:
    """Advisories that affect this package version when the scanner returns none."""
    url = (
        f"{GITHUB_API}/advisories?ecosystem=npm"
        f"&affects={quote(package_name, safe='@')}&per_page=100"
    )
    payload, error = _github_get(url)
    if error or not isinstance(payload, list):
        print(f"github advisory lookup: {error or 'unexpected response'}")
        return []
    findings = []
    for advisory in payload:
        if not isinstance(advisory, dict):
            continue
        matched = [
            entry
            for entry in advisory.get("vulnerabilities") or []
            if isinstance(entry, dict)
            and str((entry.get("package") or {}).get("name") or "").lower() == package_name.lower()
            and _range_includes(str(entry.get("vulnerable_version_range") or ""), package_version)
        ]
        if not matched:
            continue
        patched = next((_patched_version(entry) for entry in matched if _patched_version(entry)), None)
        findings.append(
            {
                "id": advisory.get("ghsa_id"),
                "severity": str(advisory.get("severity") or "unknown").lower(),
                "package": package_name,
                "installed_version": package_version,
                "fixed_version": patched,
                "description": advisory_bug_statement(advisory) or advisory.get("summary") or "",
                "advisory_url": advisory.get("html_url"),
                "scanner": "github-advisory",
                "aliases": [advisory["cve_id"]] if advisory.get("cve_id") else [],
            }
        )
    return findings


def _patched_version(entry: dict) -> str | None:
    value = entry.get("first_patched_version")
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        identifier = value.get("identifier")
        if isinstance(identifier, str) and identifier.strip():
            return identifier.strip()
    return None


def _range_includes(version_range: str, version: str) -> bool:
    text = version_range.strip()
    if not text:
        return True
    return any(_constraints_include(part, version) for part in text.split("||"))


def _constraints_include(expression: str, version: str) -> bool:
    constraints = _RANGE_CONSTRAINT.findall(expression)
    if not constraints:
        return version in expression
    current = _version_key(version)
    for operator, bound in constraints:
        target = _version_key(bound)
        if operator == "<=" and current > target:
            return False
        if operator == "<" and current >= target:
            return False
        if operator == ">=" and current < target:
            return False
        if operator == ">" and current <= target:
            return False
        if operator == "=" and current != target:
            return False
    return True


def _version_key(value: str) -> tuple[int, ...]:
    parts = [int(part) for part in re.findall(r"\d+", value)]
    return tuple(parts or [0])


def _name_list(names) -> str:
    if not isinstance(names, list) or not names:
        return "(none)"
    return ", ".join(str(name) for name in names)


def _find_vulnerability(findings: list[dict], requested_id: str) -> dict | None:
    wanted = requested_id.strip().casefold()
    for finding in findings:
        identifiers = [finding.get("id"), *(finding.get("aliases") or [])]
        if wanted in {str(item).casefold() for item in identifiers if item}:
            return finding
    return None


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run patch resolution, index, and the debugger loop.")
    parser.add_argument("--package-name", default=os.getenv("PACKAGE_NAME"))
    parser.add_argument("--package-version", default=os.getenv("PACKAGE_VERSION"))
    parser.add_argument("--source-dir", default=os.getenv("SOURCE_DIR"))
    parser.add_argument("--vulnerability-id", default=os.getenv("VULNERABILITY_ID"))
    parser.add_argument("--model-provider", default=os.getenv("MODEL_PROVIDER", "openrouter"))
    parser.add_argument("--model-name", default=os.getenv("MODEL_NAME"))
    args = parser.parse_args()
    if not args.package_name or not args.package_version:
        parser.error("--package-name and --package-version are required")
    if args.model_name and args.model_name not in patch_evaluator_models():
        parser.error(f"--model-name must be one of: {', '.join(patch_evaluator_models())}")
    return args


if __name__ == "__main__":
    main()
