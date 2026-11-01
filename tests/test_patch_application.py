"""
test_patch_application.py
=========================
Standalone test harness for patch_application.py.

Run directly — no LangGraph, no other nodes required:

    python test_patch_application.py

You can switch TEST_MODE between:
  - "file_map"  : patch is a JSON file-map  (Format 1, most common)
  - "diff"      : patch is a unified diff    (Format 2)
  - "minimal"   : bare-minimum package.json only (no real package source)

Prerequisites
-------------
  - Docker must be running.
  - Python >= 3.11 (same venv as the rest of the project).
"""

import json
import pytest
import sys
import textwrap
from pathlib import Path

# ── Make sure the project root is on the path ──────────────────────────────
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from patch_application import patch_application
from patch_application import _seed_workspace_from_source
from patch_validation import patch_validation
from state import GraphState, PatchAttempt


def test_seed_workspace_from_source_preserves_package_files(tmp_path):
    source_dir = tmp_path / "source"
    work_dir = tmp_path / "workspace"
    source_dir.mkdir()
    (source_dir / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    (source_dir / "template.js").write_text("module.exports = 'original';\n", encoding="utf-8")
    (source_dir / "node_modules").mkdir()
    (source_dir / "node_modules" / "ignored.js").write_text("ignored", encoding="utf-8")

    _seed_workspace_from_source(str(source_dir), work_dir)

    assert (work_dir / "package.json").exists()
    assert (work_dir / "template.js").read_text(encoding="utf-8") == "module.exports = 'original';\n"
    assert not (work_dir / "node_modules").exists()

# ===========================================================================
# Choose which test scenario to run
# ===========================================================================
TEST_MODE = "file_map"   # options: "file_map" | "diff" | "minimal"


# ---------------------------------------------------------------------------
# Scenario 1 – file_map
#   Patch is a JSON dict: {relative_path -> full_file_content}
#   Simulates what patch_generation would produce for a simple package.
# ---------------------------------------------------------------------------
FILE_MAP_PATCH: str = json.dumps(
    {
        "package.json": json.dumps(
            {
                "name": "test-pkg",
                "version": "1.0.0",
                "description": "Patched test package",
                "main": "index.js",
                "scripts": {
                    # Simple test: node exits 0 if require works
                    "test": "node -e \"require('./index.js'); console.log('test passed');\"",
                },
                "dependencies": {},
            },
            indent=2,
        ),
        "index.js": textwrap.dedent(
            """\
            // Patched index.js
            'use strict';

            function safeAdd(a, b) {
              if (typeof a !== 'number' || typeof b !== 'number') {
                throw new TypeError('Arguments must be numbers');
              }
              return a + b;
            }

            module.exports = { safeAdd };

            if (require.main === module) {
              console.log('safeAdd(1, 2) =', safeAdd(1, 2));
            }
            """
        ),
    }
)


# ---------------------------------------------------------------------------
# Scenario 2 – unified diff
#   Simulates a diff produced by an LLM.  The base file must already exist
#   inside the temp dir — for a brand-new package this is tricky, so we use
#   the /dev/null → new-file convention.
# ---------------------------------------------------------------------------
UNIFIED_DIFF_PATCH: str = textwrap.dedent(
    """\
    --- /dev/null
    +++ b/package.json
    @@ -0,0 +1,12 @@
    +{
    +  "name": "test-pkg-diff",
    +  "version": "1.0.0",
    +  "description": "Diff-applied test package",
    +  "main": "index.js",
    +  "scripts": {
    +    "test": "node -e \\"console.log('diff test passed')\\""
    +  },
    +  "dependencies": {}
    +}
    --- /dev/null
    +++ b/index.js
    @@ -0,0 +1,3 @@
    +'use strict';
    +module.exports = {};
    +console.log('loaded');
    """
)


# ---------------------------------------------------------------------------
# Scenario 3 – minimal (no patch content at all; relies on fallback logic)
# ---------------------------------------------------------------------------
MINIMAL_PATCH: str = ""  # triggers the fallback package.json generation


# ===========================================================================
# Build the fake GraphState
# ===========================================================================

def build_state(mode: str) -> GraphState:
    if mode == "file_map":
        diff = FILE_MAP_PATCH
    elif mode == "diff":
        diff = UNIFIED_DIFF_PATCH
    else:  # "minimal"
        diff = MINIMAL_PATCH

    patch_attempt: PatchAttempt = {
        "attempt_number": 1,
        "attempt": "123",
        "diff": diff,
        "model_used": "test-harness",
    }

    state: GraphState = {
        "model_name": "test-harness",
        "package_name": "test-pkg",
        "package_version": "1.0.0",
        "sbom": {},
        "vulnerabilities": [],
        "patch_attempts": [],
        "current_patch": patch_attempt,
        "sandbox_id": None,
        "sandbox_apply_success": None,
        "validation": None,
        "classification": None,
        "classification_reason": None,
        "errors": [],
    }
    return state


# ===========================================================================
# Entry point
# ===========================================================================

def main() -> None:
    print(f"\n{'=' * 60}")
    print(f"  patch_application  –  standalone test")
    print(f"  Mode: {TEST_MODE}")
    print(f"{'=' * 60}\n")

    state = build_state(TEST_MODE)

    # ── Run the node ────────────────────────────────────────────────────────
    result = patch_application(state)

    # ── Print the state update returned ────────────────────────────────────
    print(f"\n\n{'=' * 60}")
    print("  RETURNED STATE UPDATE")
    print(f"{'=' * 60}")
    print(f"  sandbox_id            : {result.get('sandbox_id')}")
    print(f"  sandbox_apply_success : {result.get('sandbox_apply_success')}")
    print(f"  errors                : {result.get('errors')}")

    val = result.get("validation", {})
    if val:
        print(f"\n  validation.build_succeeded        : {val.get('build_succeeded')}")
        print(f"  validation.tests_passed           : {val.get('tests_passed')}")
        print(f"  validation.revalidation_scan_clean: {val.get('revalidation_scan_clean')}")
        log_snippet = (val.get("logs") or "")[:800]
        print(f"\n  validation.logs (first 800 chars):\n{log_snippet}")

    # ── Exit code mirrors test result ───────────────────────────────────────
    success = result.get("sandbox_apply_success", False)
    print(f"\n{'=' * 60}")
    print(f"  Final result: {'PASS' if success else 'FAIL'}")
    print(f"{'=' * 60}\n")

    # Run validation node
    print(f"Patch validation test")
    state.update(result)
    patch_validation(state)

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()


def test_dockerfile_installs_git_and_dependencies_once(tmp_path):
    from patch_application import _write_dockerfile
    text = _write_dockerfile(tmp_path).read_text()
    assert 'apk add --no-cache git' in text
    assert text.count('npm install') == 1
    assert '--include=dev' in text
    assert '|| true' not in text
    assert text.index('apk add') < text.index('npm install')


def test_setup_failure_skips_tests_and_source_retry(tmp_path, monkeypatch):
    import importlib
    module = importlib.import_module('patch_application')
    from graph import route_after_classification
    monkeypatch.setattr(module, 'PATCH_WORKSPACE_ROOT', tmp_path)
    monkeypatch.setattr(module, '_seed_workspace_from_source', lambda *a: None)
    monkeypatch.setattr(module, '_write_patched_package', lambda *a: True)
    monkeypatch.setattr(module, '_build_image', lambda *a: (False, '#8 2.1 PACKAGE_INSTALL_EXIT_CODE=254\n'))
    monkeypatch.setattr(module, '_run_npm_test', lambda *a: pytest.fail('Tests must not run after install failure'))
    monkeypatch.setattr(module, '_teardown', lambda *a, **k: None)
    result = module.patch_application({'current_patch': {'diff': 'candidate'}})
    assert result['validation']['install_succeeded'] is False
    assert result['validation']['failure_stage'] == 'dependencies'
    assert result['validation']['tests_passed'] is False
    assert route_after_classification({**result, 'classification': 'fail', 'max_retries': 3}) == 'eval'


@pytest.mark.parametrize("network_failure", [False, True])
def test_successful_image_runs_tests_without_reinstall(tmp_path, monkeypatch, network_failure):
    import importlib
    module = importlib.import_module('patch_application')
    calls = []
    monkeypatch.setattr(module, 'PATCH_WORKSPACE_ROOT', tmp_path)
    monkeypatch.setattr(module, '_seed_workspace_from_source', lambda *a: None)
    monkeypatch.setattr(module, '_write_patched_package', lambda *a: True)
    monkeypatch.setattr(module, '_build_image', lambda *a: (True, '#8 2.1 PACKAGE_INSTALL_EXIT_CODE=0\n'))
    monkeypatch.setattr(module, '_select_test_command', lambda *a: ['npm', 'test'])
    monkeypatch.setattr(module, '_run_npm_test', lambda *a: (calls.append(a) or not network_failure, 'container',
        'npm error code EAI_AGAIN' if network_failure else 'tests passed'))
    monkeypatch.setattr(module, '_teardown', lambda *a, **k: None)
    result = module.patch_application({'current_patch': {'diff': 'candidate'}})
    assert result['sandbox_apply_success'] is (not network_failure)
    assert result['validation']['failure_stage'] == ('setup' if network_failure else None)
    assert result['validation']['install_succeeded'] is True
    assert len(calls) == 1
