"""
test_local_pipeline.py
======================
Local end-to-end test for the FYP patch pipeline.

Runs all five nodes in sequence:
  package_input -> vulnerability_detection -> patch_generation
      -> patch_application -> patch_validation

- model_provider defaults to "mock" (no API key needed)
- Vulnerabilities can be auto-detected OR injected via --skip-vuln-detection
- patch_application requires Docker to be running on your machine

Usage examples
--------------
# Full flow (needs npm, syft, grype, docker):
python test_local_pipeline.py --package-name lodash --package-version 4.17.15

# Skip real vuln scan, inject a mock vuln:
python test_local_pipeline.py --package-name lodash --package-version 4.17.15 --skip-vuln-detection

# Use a pre-extracted source directory (skips npm pack + extract):
python test_local_pipeline.py --package-name lodash --package-version 4.17.15 \
    --source-dir ".workspace/packages/lodash/4.17.15/source/package" --skip-vuln-detection
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Ensure sibling modules are importable
sys.path.insert(0, str(Path(__file__).resolve().parent))
load_dotenv(Path(__file__).resolve().parent / ".env")

from state import GraphState, ValidationResult
from package_input import package_input
from vulnerability_detection import vulnerability_detection
from patch_generation import patch_generation
from patch_application import patch_application
from patch_validation import patch_validation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env_bool(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _sep(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


def _mock_vulnerability(package_name: str, package_version: str) -> dict[str, Any]:
    return {
        "id": "MOCK-CVE-0001",
        "severity": "high",
        "package": package_name,
        "installed_version": package_version,
        "fixed_version": None,
        "description": "Injected mock vulnerability for local pipeline testing.",
        "advisory_url": None,
        "scanner": "mock",
        "aliases": [],
    }

# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_pipeline(args: argparse.Namespace) -> None:
    state: dict[str, Any] = {
        "package_name": args.package_name,
        "package_version": args.package_version,
        "model_provider": args.model_provider,
        "patch_scope": args.patch_scope,
        "retry_count": 0,
        "max_retries": args.max_retries,
        "errors": [],
    }
    if args.model_name:
        state["model_name"] = args.model_name

    # Pre-set source_dir if caller already extracted the package
    if args.source_dir:
        source_path = Path(args.source_dir).resolve()
        manifest = source_path / "package.json"
        if not source_path.exists():
            print(f"ERROR: --source-dir does not exist: {source_path}")
            sys.exit(1)
        state["source_dir"] = str(source_path)
        state["package_manifest_path"] = str(manifest)
        _sep("PACKAGE INPUT (skipped - using provided source_dir)")
        print(f"  source_dir : {source_path}")
    else:
        # Node 1: package_input
        _sep("NODE 1 / 5 - PACKAGE INPUT")
        result = package_input(state)
        state.update(result)
        if state.get("errors"):
            _print_errors(state)
            sys.exit(1)
        print(f"  source_dir : {state.get('source_dir')}")
        print(f"  tarball    : {state.get('tarball_path')}")

    # Node 2: vulnerability_detection
    if args.skip_vuln_detection:
        _sep("NODE 2 / 5 - VULNERABILITY DETECTION (skipped - injecting mock)")
        mock_vuln = _mock_vulnerability(args.package_name, args.package_version)
        state["vulnerabilities"] = [mock_vuln]
        state["current_vulnerabilities"] = [mock_vuln]
    else:
        _sep("NODE 2 / 5 - VULNERABILITY DETECTION")
        result = vulnerability_detection(state)
        state.update(result)
        vulns = state.get("current_vulnerabilities", [])
        print(f"  Found {len(vulns)} target vulnerabilities.")
        for vulnerability in vulns:
            print(
                f"  - {vulnerability.get('id')} ({vulnerability.get('severity')}) "
                f"in {vulnerability.get('package')}@{vulnerability.get('installed_version')}"
            )
        if not vulns:
            _print_errors(state)
            print("  No target vulnerability was detected; no patch was generated.")
            sys.exit(1)
        if state.get("errors"):
            print(f"  [warnings] {state['errors']}")
            state["errors"] = []

    # Official patch lookup (answer key). Not fed into generation.
    _sep("NODE 2b - OG PATCH RESOLUTION")
    from og_patch_resolution import og_patch_resolution
    result = og_patch_resolution(state)
    state.update(result)
    answer = state.get("answer_key") or {}
    print(f"  status          : {answer.get('status')}")
    print(f"  ghsa_id         : {answer.get('ghsa_id')}")
    print(f"  patched version : {answer.get('first_patched_version')}")
    print(f"  vendor files    : {answer.get('files') or []}")
    print(f"  vendor diff     : {len(answer.get('diff') or '')} chars")

    # Node 3: patch_generation
    _sep(f"NODE 3 / 5 - PATCH GENERATION  (provider={args.model_provider})")
    result = patch_generation(state)
    state.update(result)

    if not state.get("errors"):
        patch = state.get("current_patch") or {}
        diff = patch.get("diff", "")
        print(f"  model_used  : {patch.get('model_used')}")
        print(f"  attempt_id  : {patch.get('attempt_id')}")
        print(f"  diff length : {len(diff)} chars")
        print("\n  --- diff preview (first 500 chars) ---")
        print(textwrap.indent(diff[:500], "  "))

    if args.stop_after_patch:
        if state.get("errors"):
            _print_errors(state)
        if args.dump_state:
            _sep("PATCH GENERATION STATE")
            print(json.dumps(state, indent=2, default=str))
        return

    if state.get("current_patch"):
        # Node 4: patch_application
        _sep("NODE 4 / 5 - PATCH APPLICATION")
        result = patch_application(state)
        state.update(result)
        if state.get("errors"):
            print(f"  [errors during application] {state['errors']}")

        _sep("NODE 4b - VULNERABILITY RESCAN")
        from vulnerability_rescan import vulnerability_rescan
        result = vulnerability_rescan(state)
        state.update(result)
        remaining = state.get("remaining_vulnerabilities") or []
        print(f"  re-scan clean : {(state.get('validation') or {}).get('revalidation_scan_clean')}")
        print(f"  remaining     : {len(remaining)}")

    # Node 5: patch_validation. Generation failures also reach this node
    # for a consistent classification, but are not persisted.
    _sep("NODE 5 / 5 - PATCH VALIDATION")
    result = patch_validation(state)
    state.update(result)

    _sep("NODE 6 - PATCH SCORING  (vs maintainer patch)")
    from patch_scoring import patch_scoring
    result = patch_scoring(state)
    state.update(result)
    score = state.get("patch_score") or {}
    print(f"  status          : {score.get('status')}")
    print(f"  location        : {score.get('location')} ({score.get('location_overlap')})")
    print(f"  strategy        : {score.get('strategy')} ({score.get('strategy_generated')} vs {score.get('strategy_vendor')})")
    print(f"  completeness    : {score.get('completeness')}")
    print(f"  matched files   : {score.get('matched_files')}")
    print(f"  missing files   : {score.get('missing_files')}")

    # Final summary
    _sep("PIPELINE COMPLETE")
    print(f"  package            : {state.get('package_name')}@{state.get('package_version')}")
    print(f"  classification     : {state.get('classification', 'unknown')}")
    print(f"  classification_why : {state.get('classification_reason', '')}")
    print(f"  sandbox_success    : {state.get('sandbox_apply_success')}")
    print(f"  answer_key         : {answer.get('status')} ({answer.get('ghsa_id')})")
    print(f"  location           : {score.get('location')} ({score.get('location_overlap')})")
    print(f"  strategy           : {score.get('strategy')}")
    print(f"  completeness       : {score.get('completeness')}")
    print(f"  errors             : {state.get('errors', [])}")

    if args.dump_state:
        _sep("FULL STATE DUMP")
        print(json.dumps(state, indent=2, default=str))


def _print_errors(state: dict) -> None:
    print("\n[PIPELINE ABORTED] Errors:")
    for err in state.get("errors", []):
        print(f"  - {err}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="End-to-end local test for the FYP patch pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python test_local_pipeline.py --package-name lodash --package-version 4.17.15 --skip-vuln-detection
              python test_local_pipeline.py --package-name semver --package-version 7.5.1 --dump-state
        """),
    )
    p.add_argument("--package-name", default=os.getenv("PACKAGE_NAME"),
                   help="Falls back to PACKAGE_NAME in .env")
    p.add_argument("--package-version", default=os.getenv("PACKAGE_VERSION"),
                   help="Falls back to PACKAGE_VERSION in .env")
    p.add_argument(
        "--model-provider",
        default=os.getenv("MODEL_PROVIDER", "mock"),
        choices=["mock", "openai", "anthropic", "gemini", "openrouter"],
        help="Falls back to MODEL_PROVIDER in .env",
    )
    p.add_argument("--model-name", default=os.getenv("MODEL_NAME"),
                   help="Falls back to MODEL_NAME in .env")
    p.add_argument("--patch-scope", default=os.getenv("PATCH_SCOPE", "single"), choices=["single", "all"])
    p.add_argument("--max-retries", type=int, default=int(os.getenv("MAX_RETRIES", "0")))
    p.add_argument("--source-dir", default=os.getenv("SOURCE_DIR"),
                   help="Pre-extracted package source dir (skips npm pack + extract)")
    p.add_argument("--skip-vuln-detection", action="store_true", default=_env_bool("SKIP_VULN_DETECTION"),
                   help="Inject a mock vuln instead of running syft/grype/npm-audit")
    p.add_argument("--stop-after-patch", action="store_true", default=_env_bool("STOP_AFTER_PATCH"),
                   help="Stop after the selected model returns a patch; skips Docker and validation")
    p.add_argument("--dump-state", action="store_true", default=_env_bool("DUMP_STATE"),
                   help="Print full state dict at the end")
    args = p.parse_args()
    if not args.package_name or not args.package_version:
        p.error("--package-name/--package-version are required (pass the flag, or set "
                 "PACKAGE_NAME/PACKAGE_VERSION in .env)")
    return args


if __name__ == "__main__":
    run_pipeline(_parse_args())
