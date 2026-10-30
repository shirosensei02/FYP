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
import sys
import textwrap
from pathlib import Path

import pytest

# ── Make sure the project root is on the path ──────────────────────────────
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

import patch_application as patch_application_module
from patch_application import (
    DOCKERFILE_TEMPLATE,
    _classify_regression,
    _select_validation_commands,
    _seed_workspace_from_source,
    _validate_workspace,
    patch_application,
)
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


def _validation(success: bool):
    return {
        "validation_mode": "published_package",
        "docker_status": "PASS" if success else "FAIL",
        "installation_status": "PASS" if success else "FAIL",
        "consumer_smoke_status": "PASS" if success else "FAIL",
        "docker_image_built": success,
        "install_succeeded": success,
        "build_succeeded": None,
        "tests_passed": None,
    }


@pytest.mark.parametrize(
    ("baseline_ok", "patched_ok", "expected"),
    [
        (True, True, "NO_REGRESSION"),
        (True, False, "REGRESSION"),
        (False, False, "INCONCLUSIVE"),
        (False, True, "PATCHED_ONLY_PASS"),
    ],
)
def test_classify_regression_matrix(baseline_ok, patched_ok, expected):
    assert _classify_regression(
        _validation(baseline_ok),
        _validation(patched_ok),
    ) == expected


def test_select_validation_commands_uses_public_package_import(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo", "scripts": {"build": "tsc", "test": "vitest --run"}}),
        encoding="utf-8",
    )

    build_command, test_command = _select_validation_commands(tmp_path)

    assert build_command is None
    assert test_command[:3] == ["node", "--input-type=module", "-e"]
    assert test_command[-1] == "demo"
    assert "await import(name)" in test_command[3]


def test_select_validation_commands_falls_back_to_smoke_test(tmp_path):
    (tmp_path / "package.json").write_text('{"main":"index.js"}', encoding="utf-8")

    build_command, test_command = _select_validation_commands(tmp_path)

    assert build_command is None
    assert test_command[-1] == "."


def test_dockerfile_installs_repacked_artifact_as_consumer():
    assert "tar --exclude=./Dockerfile" in DOCKERFILE_TEMPLATE
    assert "-czf /tmp/package-artifact/package.tgz" in DOCKERFILE_TEMPLATE
    assert "npm pack" not in DOCKERFILE_TEMPLATE
    assert "npm install --prefer-offline --omit=dev" in DOCKERFILE_TEMPLATE
    assert "WORKDIR /consumer" in DOCKERFILE_TEMPLATE
    assert "npm run build" not in DOCKERFILE_TEMPLATE
    assert "npm test" not in DOCKERFILE_TEMPLATE


def test_validate_workspace_stops_after_install_failure(monkeypatch, tmp_path):
    build_results = iter([(True, "source ok"), (False, "install failed")])
    monkeypatch.setattr(patch_application_module, "_write_dockerfile", lambda path: path)
    monkeypatch.setattr(
        patch_application_module,
        "_build_image",
        lambda *args: next(build_results),
    )
    monkeypatch.setattr(patch_application_module, "_teardown", lambda *args: None)
    monkeypatch.setattr(
        patch_application_module,
        "_run_consumer_smoke",
        lambda *args: pytest.fail("consumer smoke must not run after install failure"),
    )

    result = _validate_workspace(tmp_path, "image:test", "container-test")

    assert result["docker_image_built"] is True
    assert result["install_succeeded"] is False
    assert result["build_status"] == "SKIPPED"
    assert result["test_status"] == "SKIPPED"
    assert result["consumer_smoke_status"] == "SKIPPED"
    assert result["build_succeeded"] is None
    assert result["tests_passed"] is None


def test_patch_application_compares_baseline_and_patched(monkeypatch, tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    validations = iter([_validation(True), _validation(False)])
    monkeypatch.setattr(patch_application_module, "PATCH_WORKSPACE_ROOT", tmp_path / "runs")
    monkeypatch.setattr(
        patch_application_module,
        "_validate_workspace",
        lambda *args: next(validations),
    )
    monkeypatch.setattr(
        patch_application_module,
        "_write_patched_package",
        lambda *args: True,
    )

    result = patch_application(
        {
            "package_name": "demo",
            "package_version": "1.0.0",
            "source_dir": str(source_dir),
            "current_patch": {"diff": "patch", "attempt_number": 1},
            "errors": [],
        }
    )

    assert result["regression_status"] == "REGRESSION"
    assert result["sandbox_apply_success"] is False
    assert result["baseline_validation"] == _validation(True)
    assert result["patched_validation"] == _validation(False)

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
        print(f"\n  validation.build_status           : {val.get('build_status')}")
        print(f"  validation.test_status            : {val.get('test_status')}")
        print(f"  validation.consumer_smoke_status  : {val.get('consumer_smoke_status')}")
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
