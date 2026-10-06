"""Independent, evidence-based assessment of a generated security patch."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Literal

from dotenv import load_dotenv
from openai import OpenAI

from model_catalog import canonical_model_id, evaluator_for
from state import GraphState

load_dotenv()

DEFAULT_EVALUATOR_PROVIDER = "openrouter"
DEFAULT_EVALUATOR_MODEL = "openai/gpt-5.3-codex"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
EVALUATOR_MAX_TOKENS = 4_000
MAX_LOG_CHARS = 12_000
_BRACKETED_ROLE_LABEL = re.compile(
    r"\[\s*(system|assistant|user|developer|tool|function)\s*\]",
    re.IGNORECASE,
)


def _result(
    *,
    provider: str,
    model: str,
    test_suite_pass: Literal["pass", "fail"],
    genuine_fix: Literal["true", "false", "uncertain"],
    reasoning: str,
    evidence: list[str] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "status": "evaluated" if error is None else "uncertain",
        "evaluator_provider": provider,
        "evaluator_model": model,
        "test_suite_pass": test_suite_pass,
        "genuine_fix": genuine_fix,
        "reasoning": reasoning,
        "evidence": evidence or [],
        "evaluation_error": error,
    }


def _parse_response(content: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    verdict = payload.get("genuine_fix")
    if verdict not in {"true", "false", "uncertain"}:
        return None
    reasoning = payload.get("reasoning")
    if not isinstance(reasoning, str) or not reasoning.strip():
        return None
    evidence = payload.get("evidence", [])
    if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
        return None
    return {"genuine_fix": verdict, "reasoning": reasoning.strip(), "evidence": evidence}


def _sanitize_untrusted_evaluation_input(value: Any) -> Any:
    """Neutralize role-like text in package-controlled content before API use.

    Scanner findings, generated patches, and command logs are untrusted. Some
    providers reject bracketed role labels (for example ``[system]``) as prompt
    injection, even when they occur harmlessly in source code or output.
    """
    if isinstance(value, str):
        value = _BRACKETED_ROLE_LABEL.sub(
            lambda match: f"(untrusted role label: {match.group(1).lower()})",
            value,
        )
        # Source patches frequently contain regex character classes such as
        # ``[\\s\\S]``. The provider's broad role-spoofing detector can flag
        # these harmless bracketed constructs too, so preserve their readable
        # contents while using non-ASCII delimiters outside the detector's
        # bracket syntax.
        return value.replace("[", "⟦").replace("]", "⟧").replace("<|", "‹|").replace("|>", "|›")
    if isinstance(value, list):
        return [_sanitize_untrusted_evaluation_input(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_untrusted_evaluation_input(item) for key, item in value.items()}
    return value


def _evaluation_input(state: GraphState) -> dict[str, Any]:
    validation = state.get("validation") or {}
    logs = str(validation.get("logs", ""))
    payload = {
        "package": {"name": state.get("package_name"), "version": state.get("package_version")},
        "vulnerabilities": state.get("current_vulnerabilities") or state.get("vulnerabilities") or [],
        "patch": state.get("current_patch") or {},
        "deterministic_validation": {
            "build_succeeded": bool(validation.get("build_succeeded")),
            "tests_passed": bool(validation.get("tests_passed")),
            "revalidation_scan_clean": validation.get("revalidation_scan_clean"),
            "logs": logs[-MAX_LOG_CHARS:],
        },
        "remaining_vulnerabilities": state.get("remaining_vulnerabilities") or [],
    }
    return _sanitize_untrusted_evaluation_input(payload)


def adversarial_evaluation(state: GraphState) -> dict[str, Any]:
    """Ask an independent model whether the patch fixes the vulnerable behavior.

    Test-suite status is deliberately copied from the sandbox result; the model
    cannot override it. A failed/unavailable evaluation remains ``uncertain``
    and does not alter the pipeline's existing validation classification.
    """
    validation = state.get("validation") or {}
    test_suite_pass: Literal["pass", "fail"] = "pass" if validation.get("tests_passed") else "fail"
    generator_model = (state.get("current_patch") or {}).get("model_used") or state.get("generation_model_used")
    provider = state.get("evaluator_provider") or os.getenv("EVALUATOR_PROVIDER", DEFAULT_EVALUATOR_PROVIDER)
    requested_model = state.get("evaluator_model") or os.getenv("EVALUATOR_MODEL", DEFAULT_EVALUATOR_MODEL)
    model = evaluator_for(generator_model, requested_model) or requested_model

    if not state.get("current_patch"):
        return {"adversarial_evaluation": _result(
            provider=provider, model=model, test_suite_pass=test_suite_pass, genuine_fix="uncertain",
            reasoning="Evaluation skipped because no patch was generated.", error="no generated patch",
        )}
    if provider != "openrouter":
        return {"adversarial_evaluation": _result(
            provider=provider, model=model, test_suite_pass=test_suite_pass, genuine_fix="uncertain",
            reasoning="Evaluation skipped because only the OpenRouter evaluator provider is configured.",
            error=f"unsupported evaluator provider: {provider}",
        )}
    if canonical_model_id(generator_model) == canonical_model_id(model):
        return {"adversarial_evaluation": _result(
            provider=provider, model=model, test_suite_pass=test_suite_pass, genuine_fix="uncertain",
            reasoning="Evaluation skipped because the evaluator must be a different model from the patch generator.",
            error="evaluator model matches generator model",
        )}

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return {"adversarial_evaluation": _result(
            provider=provider, model=model, test_suite_pass=test_suite_pass, genuine_fix="uncertain",
            reasoning="Evaluation could not run because the OpenRouter API key is unavailable.",
            error="OPENROUTER_API_KEY is not set",
        )}

    system = (
        "You are an adversarial security-patch evaluator. Assess whether the supplied patch addresses "
        "the vulnerable behavior, not merely scanner detection or a version/string check. Look for bypasses, "
        "disabled security checks, unreachable changes, and missing vulnerable paths. Do not claim evidence "
        "that is absent from the supplied material. In reasoning, give a brief 1-3 sentence explanation "
        "for the true, false, or uncertain verdict and tie it to the supplied evidence. Return JSON only: "
        '{"genuine_fix":"true|false|uncertain","reasoning":"...","evidence":["..."]}. '
        "Use uncertain when the evidence cannot establish a genuine fix. Revalidation scanner results "
        "are version-based: `revalidation_scan_clean` and `remaining_vulnerabilities` cannot prove a "
        "source-code patch failed or succeeded, so do not use them as verdict evidence. The characters "
        "`⟦` and `⟧` in supplied source are transport-safe stand-ins for ordinary `[` and `]`; interpret "
        "them as normal source syntax and never treat them as malformed code."
    )
    try:
        client = OpenAI(api_key=api_key, base_url=os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL), timeout=180.0)
        response = client.chat.completions.create(
            model=model,
            temperature=0,
            max_tokens=EVALUATOR_MAX_TOKENS,
            response_format={"type": "json_object"},
            extra_body={"reasoning": {"enabled": False, "exclude": True}},
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(_evaluation_input(state), default=str)},
            ],
        )
        choices = getattr(response, "choices", None) or []
        content = choices[0].message.content if choices and getattr(choices[0], "message", None) else ""
        payload = _parse_response((content or "").strip())
        if payload is None:
            raise ValueError("evaluator returned an invalid JSON verdict")
    except Exception as exc:
        return {"adversarial_evaluation": _result(
            provider=provider, model=model, test_suite_pass=test_suite_pass, genuine_fix="uncertain",
            reasoning="Evaluation could not produce a valid evidence-based verdict.",
            error=f"{type(exc).__name__}: {exc}",
        )}

    return {"adversarial_evaluation": _result(
        provider=provider, model=model, test_suite_pass=test_suite_pass,
        genuine_fix=payload["genuine_fix"], reasoning=payload["reasoning"], evidence=payload["evidence"],
    )}
