"""Classify compatibility and security outcomes, then persist the attempt.

Compatibility and vulnerability remediation are deliberately separate:

* ``compatibility_status`` reports whether the generated patch introduced a
  package regression relative to the untouched baseline.
* ``security_fix_status`` reports whether the available independent evidence
  confirms that the vulnerability was fixed.
* ``final_patch_status`` is ``PASS`` only when both dimensions pass.

Every terminal outcome is written to ``all_attempts``. Only final ``PASS``
outcomes are also written to ``successful_patches``.
"""

from __future__ import annotations

import logging
from typing import Literal

from db import save_patch_attempt, save_patch_result
from state import GraphState

logger = logging.getLogger(__name__)

CompatibilityStatus = Literal["PASS", "FAIL", "INCONCLUSIVE"]
SecurityFixStatus = Literal["PASS", "FAIL", "UNCERTAIN"]
FinalPatchStatus = Literal["PASS", "FAIL", "PARTIAL"]


def _compatibility_status(state: GraphState, validation: dict) -> CompatibilityStatus:
    regression_status = state.get("regression_status")
    if regression_status == "NO_REGRESSION":
        return "PASS"
    if regression_status == "REGRESSION":
        return "FAIL"
    if regression_status in {"INCONCLUSIVE", "PATCHED_ONLY_PASS"}:
        return "INCONCLUSIVE"

    # Backward compatibility for records produced before baseline comparison.
    if bool(validation.get("build_succeeded")) and bool(validation.get("tests_passed")):
        return "PASS"
    return "FAIL"


def _security_fix_status(state: GraphState) -> SecurityFixStatus:
    if state.get("generation_status") == "failed" or not state.get("current_patch"):
        return "FAIL"

    genuine_fix = (state.get("adversarial_evaluation") or {}).get("genuine_fix")
    maintainer_verdict = (state.get("maintainer_eval") or {}).get("verdict")

    if genuine_fix == "false" or maintainer_verdict == "INCOMPLETE":
        return "FAIL"
    if genuine_fix == "true" and maintainer_verdict == "COMPLETE":
        return "PASS"
    return "UNCERTAIN"


def _final_patch_status(
    compatibility_status: CompatibilityStatus,
    security_fix_status: SecurityFixStatus,
) -> FinalPatchStatus:
    if compatibility_status != "PASS" or security_fix_status == "FAIL":
        return "FAIL"
    if security_fix_status == "PASS":
        return "PASS"
    return "PARTIAL"


def _classification_reason(
    state: GraphState,
    compatibility_status: CompatibilityStatus,
    security_fix_status: SecurityFixStatus,
    final_patch_status: FinalPatchStatus,
) -> str:
    if state.get("generation_status") == "failed":
        return state.get("generation_error") or "Patch generation failed before sandbox validation."

    regression_status = state.get("regression_status")
    if compatibility_status == "FAIL":
        if regression_status == "REGRESSION":
            return "The baseline passed, but the patched package failed compatibility validation."
        return "Package compatibility validation failed."
    if compatibility_status == "INCONCLUSIVE":
        if regression_status == "PATCHED_ONLY_PASS":
            return "Only the patched package passed; the failed baseline makes compatibility inconclusive."
        return "The baseline package failed validation, so compatibility regression could not be determined."
    if security_fix_status == "FAIL":
        return (
            "Compatibility validation passed, but independent security evidence indicates that "
            "the generated patch did not fix the vulnerability."
        )
    if final_patch_status == "PARTIAL":
        return (
            "Compatibility validation passed, but the available security evidence is incomplete "
            "or uncertain; the patch is not considered successful."
        )
    return "Compatibility passed and independent security evidence confirmed the vulnerability fix."


def patch_validation(state: GraphState) -> dict:
    """Compute final outcome fields and persist one terminal patch attempt."""
    validation = state.get("validation") or {}
    compatibility_status = _compatibility_status(state, validation)
    security_fix_status = _security_fix_status(state)
    final_patch_status = _final_patch_status(compatibility_status, security_fix_status)
    passed = final_patch_status == "PASS"
    classification = "pass" if passed else "fail"
    reason = _classification_reason(
        state,
        compatibility_status,
        security_fix_status,
        final_patch_status,
    )

    build_status = validation.get("build_status")
    if not build_status:
        build_status = "PASS" if validation.get("build_succeeded") else "FAIL"
    test_status = validation.get("test_status")
    if not test_status:
        test_status = "PASS" if validation.get("tests_passed") else "FAIL"
    consumer_status = validation.get("consumer_smoke_status", "N/A")

    logger.info(
        "patch_validation - %s@%s [%s]: regression=%s build=%s tests=%s "
        "consumer_smoke=%s compatibility=%s security=%s final=%s",
        state.get("package_name", "?"),
        state.get("package_version", "?"),
        (state.get("current_patch") or {}).get("model_used")
        or state.get("generation_model_used", "?"),
        state.get("regression_status") or "legacy",
        build_status,
        test_status,
        consumer_status,
        compatibility_status,
        security_fix_status,
        final_patch_status,
    )

    outcome = {
        "compatibility_status": compatibility_status,
        "security_fix_status": security_fix_status,
        "final_patch_status": final_patch_status,
        "classification": classification,
        "classification_reason": reason,
    }
    persistence_state = {**state, **outcome}

    attempt_doc_id = save_patch_attempt(persistence_state, passed=passed)
    if attempt_doc_id:
        logger.info("patch_validation - attempt persisted to MongoDB _id=%s", attempt_doc_id)
    else:
        logger.warning("patch_validation - MongoDB attempt save failed (continuing)")

    if passed:
        doc_id = save_patch_result(
            persistence_state,
            passed=True,
            all_attempts_id=attempt_doc_id,
        )
        if doc_id:
            logger.info("patch_validation - successful patch persisted to MongoDB _id=%s", doc_id)
        else:
            logger.warning("patch_validation - MongoDB success save failed (continuing)")

    return {**outcome, "mongo_id": attempt_doc_id}
