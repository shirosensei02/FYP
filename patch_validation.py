"""
patch_validation.py
===================
LangGraph node: validates source-code patch outcomes and persists them to MongoDB.

Decision logic
--------------
  PASS          - compatibility and security-oracle validation both pass
  INCONCLUSIVE  - compatibility passes but security validation is unavailable
  FAIL          - regression, security failure, or incomplete compatibility validation

Every terminal outcome is written to ``all_attempts``. Passing results are also
written to ``successful_patches`` via db.save_patch_result().
Version/advisory re-scans are intentionally not a gate: a scanner can identify
the unchanged package version but cannot establish whether a source diff fixed
the vulnerable behavior.
"""

from __future__ import annotations

import logging

from cost_log import record_attempt_outcome
from failure_context import record_failure
from state import GraphState, ValidationResult
from db import save_patch_attempt, save_patch_result

logger = logging.getLogger(__name__)


def skip_package_tests(state: GraphState) -> dict:
    """The locked oracle failed and no writer attempts remain, so package tests do not run."""
    oracle = state.get("generated_patch_oracle_validation") or {}
    reason = oracle.get("reason") or "Locked oracle did not pass."
    validation = ValidationResult(
        validation_mode="published_package",
        docker_status="SKIPPED",
        installation_status="SKIPPED",
        build_status="SKIPPED",
        build_reason="Package tests were skipped because the locked oracle did not pass.",
        test_status="SKIPPED",
        test_reason=reason,
        consumer_smoke_status="SKIPPED",
        consumer_smoke_succeeded=False,
        docker_image_built=False,
        failure_stage=None,
        install_succeeded=None,
        build_succeeded=None,
        tests_passed=None,
        revalidation_scan_clean=False,
        logs="Package tests were not run.",
    )
    return {
        "package_tests_skipped": True,
        "validation": validation,
        "patched_validation": validation,
        "regression_status": None,
        "sandbox_apply_success": False,
    }


def record_locked_oracle_failure(state: GraphState) -> dict:
    """Send this attempt's oracle output to the writer. The maintainer result stays out."""
    oracle = state.get("generated_patch_oracle_validation") or {}
    reason = oracle.get("reason") or "Locked oracle did not pass."
    failure = record_failure(state, reason, stage="security_oracle")
    return {
        "retry_feedback": failure,
        "classification": "fail",
        "classification_reason": reason,
        "security_validation": "FAIL",
        "package_tests_skipped": True,
    }


def patch_validation(state: GraphState, *, save_to_db: bool | None = None) -> dict:
    """
    Reads `state.validation` produced by patch_application, decides pass/fail,
    optionally persists the attempt to MongoDB, and returns a partial state update.

    By default, DB persistence is deferred until after Node 6 (maintainer evaluation)
    so all evaluation scores and verdicts are included.
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
    compatibility_passed = validation_passed and state.get("generation_status") != "failed"

    oracle_baseline = state.get("oracle_validation") or {}
    patch_oracle_status = (state.get("generated_patch_oracle_validation") or {}).get("status")
    attempts = int(state.get("oracle_attempt_count") or 0)
    maximum = int(state.get("max_oracle_attempts") or 5)
    oracle_exhausted = oracle_baseline.get("status") == "INVALID" and attempts >= maximum
    if patch_oracle_status == "SECURITY_PASS":
        security_validation = "PASS"
    elif patch_oracle_status in {"SECURITY_FAIL", "REGRESSION"}:
        security_validation = "FAIL"
    elif (
        patch_oracle_status == "INCONCLUSIVE"
        or oracle_exhausted
        or oracle_baseline.get("status") == "ERROR"
    ):
        security_validation = "INCONCLUSIVE"
    else:
        security_validation = "SKIPPED"

    if not compatibility_passed or security_validation == "FAIL":
        classification = "fail"
    elif security_validation in {"INCONCLUSIVE", "SKIPPED"}:
        classification = "inconclusive"
    else:
        classification = "pass"
    passed = classification == "pass"

    logger.info(
        "patch_validation - %s@%s [%s]: regression=%s build=%s tests=%s consumer_smoke=%s -> %s",
        package, version, model,
        regression_status or "legacy",
        build_ok, tests_ok, consumer_smoke_ok,
        classification.upper(),
    )

    # ── DB persistence (deferred by default to maintainer_eval after Node 6) ──
    should_save = bool(state.get("save_to_db", False) if save_to_db is None else save_to_db)
    attempt_doc_id = None
    if should_save:
        attempt_doc_id = save_patch_attempt(state, passed=passed)
        if attempt_doc_id:
            logger.info("patch_validation - attempt persisted to MongoDB _id=%s", attempt_doc_id)
        else:
            logger.warning("patch_validation - MongoDB attempt save failed (continuing)")

        if passed:
            doc_id = save_patch_result(state, passed=True, all_attempts_id=attempt_doc_id)
            if doc_id:
                logger.info("patch_validation - validated patch persisted to MongoDB _id=%s", doc_id)
            else:
                logger.warning("patch_validation - MongoDB save failed (continuing)")

    # ── Build human-readable reason ───────────────────────────────────────────
    tests_skipped = bool(state.get("package_tests_skipped"))
    if tests_skipped:
        oracle_reason = (state.get("generated_patch_oracle_validation") or {}).get("reason") or "Locked oracle did not pass."
        reason = f"{oracle_reason} Package tests were not run."
    elif state.get("generation_status") == "failed":
        reason = state.get("generation_error") or "Patch generation failed before sandbox validation."
    elif regression_status == "NO_REGRESSION":
        if validation.get("validation_mode") == "published_package":
            reason = (
                "Baseline and patched consumer validation passed; no compatibility regression "
                "was detected. This does not independently confirm that the vulnerability was fixed."
            )
        else:
            reason = "Baseline and patched package validation passed; no regression was detected."
    elif compatibility_passed:
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
    if classification == "inconclusive":
        if oracle_exhausted:
            reason += (
                " Compatibility validation passed, but security validation is INCONCLUSIVE "
                "because no oracle distinguished the vulnerable and fixed versions within the attempt budget."
            )
        elif security_validation == "INCONCLUSIVE":
            reason += (
                " Compatibility validation passed, but security validation is INCONCLUSIVE "
                "because oracle execution could not complete reliably."
            )
        else:
            reason += (
                " Compatibility validation passed, but security validation was SKIPPED; "
                "the vulnerability fix remains unverified."
            )
    elif compatibility_passed and security_validation == "FAIL":
        reason += " Compatibility passed, but the generated patch failed security-oracle validation."
    # A missing or crashed oracle is a run fact. It is not a defect the writer can repair.
    writer_visible = classification != "inconclusive"
    failure = record_failure(
        state,
        reason,
        stage="security_oracle" if tests_skipped else None,
        writer_visible=writer_visible,
    ) if not passed else None
    record_attempt_outcome(state, passed=passed)
    return {
        "retry_feedback": failure if writer_visible else None,
        "classification": classification,
        "classification_reason": reason,
        "compatibility_classification": "pass" if compatibility_passed else "fail",
        "security_validation": security_validation,
        "mongo_id": attempt_doc_id,
    }
