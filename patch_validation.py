"""
patch_validation.py
===================
LangGraph node: validates source-code patch outcomes and persists them to MongoDB.

Decision logic
--------------
  PASS  - baseline and patched validation both pass (NO_REGRESSION)
  FAIL  - regression, inconclusive baseline, or incomplete validation

Every terminal outcome is written to ``all_attempts``. Passing results are also
written to ``successful_patches`` via db.save_patch_result().
Version/advisory re-scans are intentionally not a gate: a scanner can identify
the unchanged package version but cannot establish whether a source diff fixed
the vulnerable behavior.
"""

from __future__ import annotations

import logging

from failure_context import record_failure
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

    build_ok = bool(validation.get("build_succeeded"))
    tests_ok = bool(validation.get("tests_passed"))
    consumer_smoke_ok = validation.get("consumer_smoke_status") == "PASS"
    regression_status = state.get("regression_status")
    validation_passed = (
        regression_status == "NO_REGRESSION"
        if regression_status
        else build_ok and tests_ok
    )
    passed = validation_passed and state.get("generation_status") != "failed"

    logger.info(
        "patch_validation - %s@%s [%s]: regression=%s build=%s tests=%s consumer_smoke=%s -> %s",
        package, version, model,
        regression_status or "legacy",
        build_ok, tests_ok, consumer_smoke_ok,
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
        doc_id = save_patch_result(state, passed=True, all_attempts_id=attempt_doc_id)
        if doc_id:
            logger.info("patch_validation - validated patch persisted to MongoDB _id=%s", doc_id)
        else:
            logger.warning("patch_validation - MongoDB save failed (continuing)")

    # ── Build human-readable reason ───────────────────────────────────────────
    if state.get("generation_status") == "failed":
        reason = state.get("generation_error") or "Patch generation failed before sandbox validation."
    elif regression_status == "NO_REGRESSION":
        if validation.get("validation_mode") == "published_package":
            reason = (
                "Baseline and patched consumer validation passed; no compatibility regression "
                "was detected. This does not independently confirm that the vulnerability was fixed."
            )
        else:
            reason = "Baseline and patched package validation passed; no regression was detected."
    elif passed:
        reason = "Docker build succeeded and package validation passed."
    elif state.get("patch_applied") is False:
        reason = "Patch could not be applied to the source; Docker build was not run."
    elif validation.get("failure_stage") == "dependencies":
        reason = "Dependency installation failed; package tests were skipped."
    elif validation.get("failure_stage") == "setup":
        reason = "Sandbox environment setup failed; package validation could not complete reliably."
    elif regression_status == "REGRESSION":
        reason = "The baseline passed, but the patched package failed validation."
    elif regression_status == "INCONCLUSIVE":
        reason = "The baseline package failed validation, so patch regression could not be determined."
    elif regression_status == "PATCHED_ONLY_PASS":
        reason = "Only the patched package passed; the failed baseline makes the comparison inconclusive."
    elif not build_ok:
        reason = "Docker build failed — patch could not be applied."
    elif not tests_ok and validation.get("install_succeeded") is False:
        reason = "Dependency installation failed; package validation could not complete reliably."
    elif not tests_ok:
        reason = "Build succeeded but npm test failed — patch broke the package."
    failure = record_failure(state, reason) if not passed else None
    return {
        "retry_feedback": failure,
        "classification": "pass" if passed else "fail",
        "classification_reason": reason,
        "mongo_id": attempt_doc_id,
    }
