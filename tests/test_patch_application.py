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

# ── Make sure the project root is on the path ──────────────────────────────
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from patch_application import patch_application
from patch_validation import patch_validation
from state import GraphState, PatchAttempt

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
        "retry_count": 0,
        "max_retries": 3,
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
