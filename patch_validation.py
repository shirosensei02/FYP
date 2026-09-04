"""
patch_validation.py
===================
LangGraph node: validates the patch outcome and persists the result to MongoDB.

Decision logic
--------------
  PASS  ─ build succeeded  AND  tests passed
  FAIL  ─ anything else

The result (both pass and fail) is written to MongoDB via db.save_patch_result()
so the full experiment history is preserved for manual analysis.
"""

from __future__ import annotations

import logging

from state import GraphState
from db import save_patch_result

logger = logging.getLogger(__name__)


def patch_validation(state: GraphState) -> dict:
    """
    Reads `state.validation` produced by patch_application, decides pass/fail,
    persists to MongoDB, and returns a partial state update.
    """
    validation = state.get("validation") or {}
    package    = state.get("package_name", "?")
    version    = state.get("package_version", "?")
    model      = (state.get("current_patch") or {}).get("model_used", "?")

    build_ok   = bool(validation.get("build_succeeded"))
    tests_ok   = bool(validation.get("tests_passed"))
    scan_clean = bool(validation.get("revalidation_scan_clean"))
    passed     = build_ok and tests_ok and scan_clean

    logger.info(
        "patch_validation - %s@%s [%s]: build=%s tests=%s → %s",
        package, version, model,
        build_ok, tests_ok,
        "PASS" if passed else "FAIL",
    )

    # ── Persist to MongoDB ────────────────────────────────────────────────────
    doc_id = save_patch_result(state, passed)
    if doc_id:
        logger.info("patch_validation - persisted to MongoDB _id=%s", doc_id)
    else:
        logger.warning("patch_validation - MongoDB save failed (continuing)")

    # ── Build human-readable reason ───────────────────────────────────────────
    if passed:
        reason = "Build succeeded, all tests passed, and the vulnerability re-scan was clean."
    elif not build_ok:
        reason = "Docker build failed — patch could not be applied."
    elif not tests_ok:
        reason = "Build succeeded but npm test failed — patch broke the package."
    else:
        reason = "Build and tests passed, but the vulnerability re-scan was not clean."

    return {
        "classification": "pass" if passed else "fail",
        "classification_reason": reason,
    }
