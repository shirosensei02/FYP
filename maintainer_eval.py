"""
maintainer_eval.py
==================
LangGraph node: **Maintainer Evaluation (LLM-based)**

Performs a qualitative, LLM-driven comparison of the generated patch against
the official answer-key patch, in the context of the vulnerability being fixed.

Key behaviours
--------------
* Filters out test-related file hunks from the answer-key diff so the
  comparison is apples-to-apples with the generated diff (which only patches
  vulnerability source files).
* Sends both diffs plus the vulnerability description to an LLM and asks for
  a structured verdict (PASS / PARTIAL / FAIL) with explanations.
* Persists the result in ``GraphState["maintainer_eval"]``.

GraphState keys consumed
------------------------
- ``current_patch``       : PatchAttempt — the generated diff
- ``answer_key``          : AnswerKey    — the vendor diff
- ``vulnerabilities``     : list[Vulnerability]
- ``current_vulnerabilities`` : list[Vulnerability]

GraphState keys produced
------------------------
- ``maintainer_eval`` : MaintainerEvalResult
- ``errors``          : list[str]  (appended on failure)
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from state import GraphState, MaintainerEvalResult

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "maintainer_eval.txt"
MAX_TOKENS = 4_096

# Patterns that identify test-related paths in a unified diff
_TEST_PATH_PATTERNS = (
    re.compile(r"[/\\]tests?[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]__tests__[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]spec[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]__mocks__[/\\]", re.IGNORECASE),
    re.compile(r"\.test\.[jt]sx?$", re.IGNORECASE),
    re.compile(r"\.spec\.[jt]sx?$", re.IGNORECASE),
    re.compile(r"_test\.[jt]sx?$", re.IGNORECASE),
    re.compile(r"[/\\]test\.[jt]sx?$", re.IGNORECASE),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pick_vulnerability(state: GraphState) -> dict[str, Any]:
    """Return the primary vulnerability dict for prompt rendering."""
    vulns = state.get("current_vulnerabilities") or state.get("vulnerabilities") or []
    if vulns:
        return vulns[0]
    return {}


def _build_prompt(
    generated_diff: str,
    answer_key_diff: str,
    vulnerability: dict[str, Any],
) -> str:
    """Render the evaluation prompt from the template file."""
    if not PROMPT_PATH.is_file():
        raise FileNotFoundError(f"Prompt template not found: {PROMPT_PATH}")

    template = PROMPT_PATH.read_text(encoding="utf-8")
    return template.format(
        vulnerability_id=vulnerability.get("id", "unknown"),
        vulnerability_severity=vulnerability.get("severity", "unknown"),
        vulnerability_description=vulnerability.get("description", "No description available."),
        generated_diff=generated_diff or "(no diff produced)",
        answer_key_diff=answer_key_diff or "(no answer-key diff available)",
    )


def _parse_eval_response(content: str) -> MaintainerEvalResult | None:
    """Try to parse the LLM response into a MaintainerEvalResult."""
    # Strip markdown fences if the model wrapped the JSON
    cleaned = re.sub(r"^```(?:json)?\s*", "", content.strip())
    cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    verdict = payload.get("verdict", "").upper()
    if verdict not in {"COMPLETE", "PARTIAL", "INCOMPLETE"}:
        verdict = "INCOMPLETE"

    return MaintainerEvalResult(
        status="evaluated",
        verdict=verdict,
        root_cause_identified=bool(payload.get("root_cause_identified", False)),
        same_fix_strategy=bool(payload.get("same_fix_strategy", False)),
        summary=payload.get("summary"),
        differences=payload.get("differences", []),
        missing_from_generated=payload.get("missing_from_generated", []),
        extra_in_generated=payload.get("extra_in_generated", []),
    )


def _call_llm(prompt: str, eval_model) -> str:
    """Send the evaluation prompt to the LLM via OpenRouter and return raw content."""
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set")

    client = OpenAI(
        api_key=api_key,
        base_url=os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL),
        timeout=180.0,
    )

    system_message = (
        "You are a senior security engineer reviewing patches. "
        "Return ONLY a JSON object as specified in the prompt. "
        "No markdown fences, no explanation outside the JSON."
    )

    response = client.chat.completions.create(
        model=eval_model,
        temperature=0,
        max_tokens=MAX_TOKENS,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": prompt},
        ],
    )

    choices = getattr(response, "choices", None) or []
    if not choices:
        raise RuntimeError("LLM returned no choices")

    message = getattr(choices[0], "message", None)
    if message is None:
        raise RuntimeError("LLM returned no message")

    return (message.content or "").strip()


# ===========================================================================
# Public LangGraph node
# ===========================================================================

def maintainer_eval(state: GraphState) -> dict:
    """
    LangGraph node — **Maintainer Evaluation**

    Compares the generated patch diff against the answer-key diff using an
    LLM to produce a qualitative verdict with explanatory details.

    Parameters
    ----------
    state : GraphState

    Returns
    -------
    dict
        Partial GraphState update with ``maintainer_eval`` (and possibly
        appended ``errors``).
    """
    errors: list[str] = list(state.get("errors", []))
    eval_model = state.get("adversarial_evaluation").get("evaluator_model")

    # ── Gather inputs ──────────────────────────────────────────────────────
    current_patch = state.get("current_patch") or {}
    generated_diff = current_patch.get("diff", "")

    answer_key = state.get("answer_key") or {}
    answer_key_diff = answer_key.get("diff", "")

    vulnerability = _pick_vulnerability(state)

    # ── Guard: skip if there is nothing to compare ─────────────────────────
    if not generated_diff and not answer_key_diff:
        result = MaintainerEvalResult(
            status="skipped",
            summary="No generated diff and no answer-key diff available for comparison.",
        )
        return {"maintainer_eval": result}

    if not answer_key_diff:
        result = MaintainerEvalResult(
            status="skipped",
            summary="No answer-key diff available; maintainer evaluation skipped.",
        )
        return {"maintainer_eval": result}

    if not generated_diff:
        result = MaintainerEvalResult(
            status="evaluated",
            verdict="INCOMPLETE",
            root_cause_identified=False,
            same_fix_strategy=False,
            summary="No generated diff was produced; the vulnerability was not addressed.",
            differences=[],
            missing_from_generated=["Entire answer-key patch is missing from generated output."],
            extra_in_generated=[],
        )
        return {"maintainer_eval": result}

    # ── Build prompt and call LLM ──────────────────────────────────────────
    try:
        prompt = _build_prompt(generated_diff, answer_key_diff, vulnerability)
        raw_response = _call_llm(prompt, eval_model)
        result = _parse_eval_response(raw_response)

        if result is None:
            preview = raw_response[:300].replace("\n", " ")
            msg = f"maintainer_eval: failed to parse LLM response (preview={preview!r})"
            logger.warning(msg)
            errors.append(msg)
            result = MaintainerEvalResult(
                status="error",
                error_message=msg,
            )

    except Exception as exc:
        msg = f"maintainer_eval: {type(exc).__name__}: {exc}"
        logger.exception(msg)
        errors.append(msg)
        result = MaintainerEvalResult(
            status="error",
            error_message=msg,
        )

    return {"maintainer_eval": result, "errors": errors}
