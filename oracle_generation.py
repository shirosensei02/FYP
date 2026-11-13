"""Generate a constrained external security regression oracle.

The model returns JavaScript only; setup commands and Docker options are owned
by the pipeline.  The script must emit one machine-readable ``ORACLE_RESULT``
line so a crash cannot be mistaken for a blocked exploit.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from openai import OpenAI

from cost_log import record_request
from prompt_variant import prompt_path
from run_cost import response_cost
from state import GraphState, OracleSpec


OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MAX_ATTEMPTS = int(os.getenv("MAX_ORACLE_ATTEMPTS", "5"))
MAX_ORACLE_SOURCE_CHARS = 32_000
MAX_CONTEXT_CHARS = 48_000
MAX_FEEDBACK_SOURCE_CHARS = 12_000
MAX_FEEDBACK_STREAM_CHARS = 4_000
ALLOWED_REQUIREMENTS = {
    "requires_git_repository",
    "requires_writable_tmp",
    "requires_fixture_files",
}

# The oracle may inspect files in /tmp, but it must not directly launch
# processes or open sockets.  The package under test is the only code that
# should be capable of triggering the target behavior.
_DANGEROUS_MODULES = r"child_process|worker_threads|cluster|net|dgram|tls|http|https"
_FORBIDDEN_SOURCE = re.compile(
    rf"(?:require|import)\s*\(\s*['\"](?:node:)?(?:{_DANGEROUS_MODULES})['\"]"
    rf"|\bfrom\s*['\"](?:node:)?(?:{_DANGEROUS_MODULES})['\"]"
    r"|\b(?:eval|Function|fetch)\s*\(|process\.(?:binding|dlopen|mainModule)\b",
)


def _target_vulnerability(state: GraphState) -> dict[str, Any]:
    vulnerabilities = state.get("current_vulnerabilities") or state.get("vulnerabilities") or []
    return dict(vulnerabilities[0]) if vulnerabilities else {}


def _source_context(state: GraphState) -> list[dict[str, str]]:
    supplied = state.get("localized_context_files") or []
    context: list[dict[str, str]] = []
    used = 0
    for item in supplied:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or item.get("file") or "unknown")
        contents = str(item.get("content") or item.get("contents") or "")
        remaining = MAX_CONTEXT_CHARS - used
        if remaining <= 0:
            break
        clipped = contents[:remaining]
        context.append({"path": path, "content": clipped})
        used += len(clipped)

    if context:
        return context

    source_dir = Path(str(state.get("source_dir") or ""))
    for rel in ("package.json", "index.js", "lib/index.js", "src/index.js"):
        candidate = source_dir / rel
        if not candidate.is_file():
            continue
        contents = candidate.read_text(encoding="utf-8", errors="replace")
        remaining = MAX_CONTEXT_CHARS - used
        if remaining <= 0:
            break
        context.append({"path": rel, "content": contents[:remaining]})
        used += min(len(contents), remaining)
    return context


def _prompt(state: GraphState) -> str:
    answer = dict(state.get("answer_key") or {})
    vulnerability = _target_vulnerability(state)
    payload = {
        "ghsa_id": answer.get("ghsa_id") or vulnerability.get("id"),
        "package": state.get("package_name"),
        "vulnerable_version": state.get("package_version"),
        "advisory": {
            "ghsa_id": answer.get("ghsa_id"),
            "cve_id": answer.get("cve_id"),
            "summary": answer.get("summary"),
            "advisory_url": answer.get("advisory_url"),
        },
        "vulnerability": vulnerability,
        "maintainer_patch": {
            "summary": answer.get("summary"),
            "first_patched_version": answer.get("first_patched_version"),
            "files": answer.get("files") or [],
            "diff": answer.get("diff"),
        },
        "source_context": _source_context(state),
        "previous_failure": _bounded_feedback(state),
    }
    suffix = str(state.get("prompt_suffix") or "").strip()
    if suffix in {"_generic", "_CoT"}:
        vulnerability = _target_vulnerability(state)
        payload = {
            "package": state.get("package_name"),
            "vulnerable_version": state.get("package_version"),
            "description": vulnerability.get("description") or "",
            "source_context": payload["source_context"],
            "previous_failure": payload["previous_failure"],
        }
    instruction = prompt_path("oracle", suffix).read_text(encoding="utf-8")
    failure = payload.get("previous_failure")
    note = str(failure.get("revision") or "").strip() if isinstance(failure, dict) else ""
    sections = [instruction.rstrip()]
    if note:
        sections.append("PREVIOUS RUN:\n" + note)
    sections.append("INPUT:\n" + json.dumps(payload, ensure_ascii=False, default=str))
    return "\n\n".join(sections)


def _bounded_feedback(state: GraphState) -> dict[str, Any] | None:
    """Return useful correction context without feeding unbounded logs back to the model."""
    feedback = state.get("oracle_feedback")
    if not feedback:
        return None

    bounded = dict(feedback)
    candidate = state.get("oracle_candidate") or {}
    source = str(candidate.get("source") or "")
    if source:
        bounded["previous_oracle_source"] = source[:MAX_FEEDBACK_SOURCE_CHARS]
    for baseline in ("vulnerable", "fixed"):
        execution = bounded.get(baseline)
        if not isinstance(execution, dict):
            continue
        clipped = dict(execution)
        for stream in ("stdout", "stderr"):
            if stream in clipped:
                clipped[stream] = str(clipped.get(stream) or "")[-MAX_FEEDBACK_STREAM_CHARS:]
        bounded[baseline] = clipped
    return bounded


def _json_text(content: str) -> str:
    """Drop a Markdown fence so a wrapped JSON object can be parsed."""
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, count=1, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
        return text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if fenced and not text.startswith("{"):
        return fenced.group(1).strip()
    return text


def _parse_candidate(content: str, attempt: int, model: str | None) -> OracleSpec | str:
    try:
        payload = json.loads(_json_text(content))
    except json.JSONDecodeError as exc:
        return f"model response was not JSON: {exc}"
    if not isinstance(payload, dict):
        return "model response must be a JSON object"
    source = payload.get("source")
    if not isinstance(source, str) or not source.strip():
        return "model response did not contain non-empty source"
    if len(source) > MAX_ORACLE_SOURCE_CHARS:
        return f"oracle source exceeds {MAX_ORACLE_SOURCE_CHARS} characters"
    if "ORACLE_RESULT " not in source:
        return "oracle source does not emit the ORACLE_RESULT protocol"
    requirements = payload.get("requirements", [])
    if not isinstance(requirements, list) or any(
        not isinstance(item, str) or item not in ALLOWED_REQUIREMENTS
        for item in requirements
    ):
        return "oracle requirements contain an unsupported trusted fixture"
    forbidden = _FORBIDDEN_SOURCE.search(source)
    if forbidden:
        return f"oracle source contains forbidden capability: {forbidden.group(0)}"
    return OracleSpec(
        status="generated",
        attempt_number=attempt,
        language="javascript",
        source=source,
        explanation=str(payload.get("explanation") or ""),
        requirements=list(dict.fromkeys(requirements)),
        timeout_seconds=30,
        model_used=model,
    )


def _response_source(content: str) -> str:
    """Recover a rejected candidate's source so the next attempt can correct it."""
    try:
        payload = json.loads(_json_text(content))
    except (json.JSONDecodeError, TypeError):
        return ""
    source = payload.get("source") if isinstance(payload, dict) else None
    return source[:MAX_ORACLE_SOURCE_CHARS] if isinstance(source, str) else ""


def oracle_generation(state: GraphState) -> dict:
    """Generate one candidate; graph routing owns the bounded correction loop."""
    attempt = int(state.get("oracle_attempt_count") or 0) + 1
    maximum = int(state.get("max_oracle_attempts") or DEFAULT_MAX_ATTEMPTS)
    attempts = list(state.get("oracle_attempts") or [])
    base = {"oracle_attempt_count": attempt, "max_oracle_attempts": maximum}

    answer = state.get("answer_key") or {}
    if not answer.get("diff") and not answer.get("first_patched_version"):
        candidate = OracleSpec(
            status="skipped", attempt_number=attempt, language="javascript", source="",
            explanation="No maintainer diff or fixed package version is available for baseline validation.",
            timeout_seconds=30, model_used=None,
        )
        attempts.append({"attempt_number": attempt, "generation": dict(candidate)})
        return {**base, "oracle_candidate": candidate, "oracle_attempts": attempts}

    provider = state.get("model_provider", "mock")
    if provider == "mock":
        candidate = OracleSpec(
            status="skipped", attempt_number=attempt, language="javascript", source="",
            explanation="Oracle generation is skipped for the mock model provider.",
            timeout_seconds=30, model_used=None,
        )
        attempts.append({"attempt_number": attempt, "generation": dict(candidate)})
        return {**base, "oracle_candidate": candidate, "oracle_attempts": attempts}
    if provider != "openrouter":
        candidate = OracleSpec(
            status="failed", attempt_number=attempt, language="javascript", source="",
            explanation=f"Oracle generation does not support provider {provider!r}.",
            timeout_seconds=30, model_used=state.get("model_name"),
        )
        attempts.append({"attempt_number": attempt, "generation": dict(candidate)})
        return {**base, "oracle_candidate": candidate, "oracle_attempts": attempts}

    api_key = os.getenv("OPENROUTER_API_KEY")
    model = state.get("model_name") or "anthropic/claude-sonnet-5"
    if not api_key:
        message = "OPENROUTER_API_KEY is not set"
        candidate = OracleSpec(
            status="failed", attempt_number=attempt, language="javascript", source="",
            explanation=message, timeout_seconds=30, model_used=model,
        )
        attempts.append({"attempt_number": attempt, "generation": dict(candidate)})
        return {**base, "oracle_candidate": candidate, "oracle_attempts": attempts}

    client = OpenAI(
        api_key=api_key,
        base_url=os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL),
        timeout=180.0,
    )
    response = None
    request_failed = False
    try:
        response = client.chat.completions.create(
            model=model,
            temperature=0,
            max_tokens=12_000,
            response_format={"type": "json_object"},
            extra_body={"reasoning": {"enabled": False, "exclude": True}},
            messages=[
                {"role": "system", "content": "Return one JSON oracle object and nothing else."},
                {"role": "user", "content": _prompt(state)},
            ],
        )
        record_request(state, node="oracle_generation", call="generate", model=model, response=response)
        choices = getattr(response, "choices", None) or []
        raw_content = getattr(choices[0].message, "content", None) if choices else None
        content = raw_content.strip() if isinstance(raw_content, str) else ""
        parsed = _parse_candidate(content, attempt, model)
    except Exception as exc:
        message = f"oracle generation request failed: {type(exc).__name__}: {exc}"
        record_request(state, node="oracle_generation", call="generate", model=model, error=message)
        parsed = message
        request_failed = True

    if isinstance(parsed, str):
        candidate = OracleSpec(
            status="failed" if request_failed else "invalid",
            attempt_number=attempt, language="javascript",
            source="" if request_failed else _response_source(content),
            explanation=parsed, timeout_seconds=30, model_used=model,
        )
    else:
        candidate = parsed
    attempts.append({"attempt_number": attempt, "generation": dict(candidate)})
    return {
        **base,
        "oracle_candidate": candidate,
        "oracle_attempts": attempts,
        "run_cost": float(state.get("run_cost") or 0) + response_cost(response),
    }
