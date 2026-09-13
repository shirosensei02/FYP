"""
patch_validation.py
===================
LangGraph node: validates source-code patch outcomes and persists them to MongoDB.

Decision logic
--------------
  PASS  ─ build succeeded  AND  tests passed
  FAIL  ─ anything else

Every terminal outcome is written to ``all_attempts``. Passing results are also
written to ``successful_patches`` via db.save_patch_result().
Version/advisory re-scans are intentionally not a gate: a scanner can identify
the unchanged package version but cannot establish whether a source diff fixed
the vulnerable behavior.
"""

from __future__ import annotations

import logging

from state import GraphState
from db import save_patch_attempt, save_patch_result

logger = logging.getLogger(__name__)


def patch_validation(state: GraphState) -> dict:
    """
    Reads `state.validation` produced by patch_application, decides pass/fail,
    persists the attempt to MongoDB, and returns a partial state update.
    """
    validation = state.get("validation") or {}
    package    = state.get("package_name", "?")
    version    = state.get("package_version", "?")
    model      = (state.get("current_patch") or {}).get("model_used") or state.get("generation_model_used", "?")

    build_ok   = bool(validation.get("build_succeeded"))
    tests_ok   = bool(validation.get("tests_passed"))
    passed     = build_ok and tests_ok

    logger.info(
        "patch_validation - %s@%s [%s]: build=%s tests=%s → %s",
        package, version, model,
        build_ok, tests_ok,
        "PASS" if passed else "FAIL",
    )

    # ── Persist every terminal outcome ───────────────────────────────────────
    attempt_doc_id = save_patch_attempt(state, passed=passed)
    if attempt_doc_id:
        logger.info("patch_validation - attempt persisted to MongoDB _id=%s", attempt_doc_id)
    else:
        logger.warning("patch_validation - MongoDB attempt save failed (continuing)")

    # ── Persist validated patches in the success-only collection ─────────────
    if passed:
        doc_id = save_patch_result(state, passed=True)
        if doc_id:
            logger.info("patch_validation - validated patch persisted to MongoDB _id=%s", doc_id)
        else:
            logger.warning("patch_validation - MongoDB save failed (continuing)")

    # ── Build human-readable reason ───────────────────────────────────────────
    if state.get("generation_status") == "failed":
        reason = state.get("generation_error") or "Patch generation failed before sandbox validation."
    elif passed:
        reason = "Docker build succeeded and package validation passed."
    elif not build_ok:
        reason = "Docker build failed — patch could not be applied."
    elif not tests_ok:
        reason = "Build succeeded but npm test failed — patch broke the package."
    return {
        "classification": "pass" if passed else "fail",
        "classification_reason": reason,
    }
