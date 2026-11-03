"""Debugger loop: advisory and catalog stay in the first user message.

Later turns resend that message and replace only the current function bodies.
No provider prompt cache is requested. Dropped bodies leave the prompt and
remain requestable.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from cost_log import record_request
from run_cost import response_cost, response_usage
from symbol_index import MAX_BODY_LOADS, lookup_bodies, scan_source

load_dotenv()
logger = logging.getLogger(__name__)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEBUG_MAX_TOKENS = 2_000
MAX_DEBUG_ROUNDS = 20
MAX_DEBUG_PROMPT_CHARS = 256_000
# Temporary overall cost cap.
TEMP_COST_CAP = 2.0
_TERMINAL = {"located", "cannot_locate", "capped"}

_SYSTEM = (
    "You locate vulnerable functions. You are not told the package name or version. "
    "Use only the advisory and the catalog in the conversation. "
    "Reply with one JSON object and nothing else.\n"
    'Lookup: {"action":"lookup","request":["file.js:name"],"drop":["file.js:other"],"reason":"why these functions might contain the bug"}\n'
    'Found: {"action":"located","locations":[{"path":"file.js","function":"name","reason":"how this loaded body produces the vulnerable behavior"}]}\n'
    'Give up: {"action":"cannot_locate"}\n'
    "Request as many functions as you need. drop removes bodies that are unrelated. "
    "A dropped name stays in the catalog and may be requested again. "
    "A body that does not fit in the prompt is left out and is not marked retrieved, so you can request it again. "
    "The catalog message is the list of files and functions you can ask for. "
    "Every lookup includes reason. "
    "Return located only when the loaded function bodies show the vulnerable behavior. "
    "Each reason must describe the operation in that loaded body and how that operation produces the advisory's effect. "
    "A function name that matches the advisory is not enough. "
    "If the loaded bodies do not show that behavior, return lookup for the functions you still need. "
    "If the vulnerable behavior is split across files, return each function in locations."
)


def route_after_index(state: dict) -> str:
    if state.get("debug_status") in _TERMINAL:
        return "generation"
    return "debugger"


def route_after_debugger(state: dict) -> str:
    if state.get("debug_request") or state.get("debug_status") == "running":
        return "index"
    return "generation"


def debugger_node(state: dict) -> dict:
    """Ask the model whether the current bodies are enough."""
    if state.get("debug_status") in _TERMINAL:
        return {"debug_request": None}

    rounds = int(state.get("debug_rounds") or 0)
    loads = int(state.get("debug_body_loads") or 0)
    if float(state.get("run_cost") or 0) > TEMP_COST_CAP:
        return {
            "debug_status": "capped",
            "debug_request": None,
            "debug_rounds": rounds,
            "debug_feedback": f"cost cap ${TEMP_COST_CAP:.2f} exceeded",
        }
    if rounds >= MAX_DEBUG_ROUNDS or loads >= MAX_BODY_LOADS:
        return {"debug_status": "capped", "debug_request": None, "debug_rounds": rounds}

    messages = build_messages(state)
    if _prompt_chars(messages) > MAX_DEBUG_PROMPT_CHARS:
        return {"debug_status": "capped", "debug_request": None, "debug_rounds": rounds}

    run_id = state.get("run_attempt_id") or f"{state.get('package_name') or 'package'}-{uuid.uuid4()}"
    provider = state.get("model_provider", "mock")
    if provider == "mock":
        action, cost, usage = _mock_action(state), 0.0, _empty_usage()
    elif provider == "openrouter":
        action, cost, usage = _openrouter_action({**state, "run_attempt_id": run_id}, messages)
    else:
        action, cost, usage = {"action": "cannot_locate"}, 0.0, _empty_usage()

    spent = float(state.get("run_cost") or 0) + cost
    actions = list(state.get("debug_actions") or [])
    actions.append(action)
    base = {
        "run_attempt_id": run_id,
        "run_cost": spent,
        "debug_actions": actions,
        "debug_rounds": rounds + 1,
        "debug_request": None,
        "debug_usage": usage,
        "debug_prompt_chars": _prompt_chars(messages),
    }
    kind = action.get("action")
    if kind == "lookup":
        return {
            **base,
            "debug_status": "running",
            "debug_feedback": None,
            "debug_request": {
                "request": [str(item) for item in action.get("request") or [] if str(item).strip()],
                "drop": [str(item) for item in action.get("drop") or [] if str(item).strip()],
            },
        }
    if kind == "located" and _located_explains(action, state):
        return {
            **base,
            "debug_status": "located",
            "debug_feedback": None,
            "debug_locations": _locations_with_bodies(state, action.get("locations") or []),
        }
    if kind == "located":
        action["accepted"] = False
        return {
            **base,
            "debug_status": "running",
            "debug_feedback": (
                "located was not accepted. A matching function name is not enough. "
                "Explain how the loaded function bodies produce the vulnerable behavior, "
                "or look up the functions that show it."
            ),
        }
    return {**base, "debug_status": "cannot_locate", "debug_feedback": None, "debug_locations": []}


def build_messages(state: dict) -> list[dict[str, str]]:
    """Advisory and catalog occupy a stable user message. Bodies are the next one."""
    findings = state.get("current_vulnerabilities") or state.get("vulnerabilities") or []
    finding = findings[0] if findings else {}
    description = str(finding.get("description") or "")
    lines = [
        "Advisory:",
        f"id: {finding.get('id', 'unknown')}",
        f"severity: {finding.get('severity', 'unknown')}",
        f"description: {description}",
    ]
    summary = _stripped_summary(state, finding)
    if summary and summary.casefold() not in description.casefold():
        lines.append(f"summary: {summary}")
    lines.extend(["", "Catalog:", state.get("symbol_catalog") or "(no functions found)"])
    advisory = "\n".join(lines)
    return [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": advisory},
        {"role": "user", "content": _body_message(state)},
    ]


def _stripped_summary(state: dict, finding: dict) -> str:
    """GitHub advisory summary with package name and version removed."""
    answer = state.get("answer_key") or {}
    if answer.get("status") == "error":
        return ""
    summary = answer.get("summary")
    if not isinstance(summary, str):
        return ""
    text = summary.strip()
    if not text or text.lower().startswith("github api"):
        return ""
    tokens = [
        state.get("package_name"),
        state.get("package_version"),
        finding.get("package"),
        finding.get("installed_version"),
        finding.get("fixed_version"),
        answer.get("first_patched_version"),
    ]
    for token in tokens:
        if not isinstance(token, str):
            continue
        token = token.strip()
        if len(token) < 2:
            continue
        text = re.sub(re.escape(token), "", text, flags=re.IGNORECASE)
        text = re.sub(rf"v{re.escape(token)}", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s+([,.;:])", r"\1", text)
    text = text.strip(" ,.;:-")
    if len(text) < 8:
        return ""
    return text


def _body_message(state: dict) -> str:
    retrieved = state.get("debug_retrieved") or []
    if retrieved:
        seen = ", ".join(
            f"{item.get('label') or item.get('key')} ({item.get('status', 'seen')})"
            for item in retrieved
        )
    else:
        seen = "none"
    bodies = state.get("debug_in_prompt") or []
    if not bodies:
        body_text = "none"
    else:
        chunks = [
            f"--- {item.get('path')} {item.get('name')} ---\n{item.get('body', '')}"
            for item in bodies
        ]
        body_text = "\n\n".join(chunks)
    turns = []
    for index, action in enumerate(state.get("debug_actions") or [], start=1):
        kind = action.get("action")
        if kind == "lookup":
            turns.append(
                f"{index}. lookup request={action.get('request') or []} drop={action.get('drop') or []}"
            )
        else:
            turns.append(f"{index}. {kind}")
    history = "\n".join(turns) if turns else "none"
    feedback = state.get("debug_feedback") or ""
    notice = f"Not accepted:\n{feedback}\n\n" if feedback else ""
    return (
        f"{notice}"
        f"Previous actions:\n{history}\n\n"
        f"already retrieved: {seen}\n\n"
        f"Function bodies:\n{body_text}"
    )


def _locations_with_bodies(state: dict, locations: list) -> list[dict[str, str]]:
    available = {
        item.get("key"): item
        for item in state.get("debug_in_prompt") or []
        if item.get("key")
    }
    by_name = {}
    for item in state.get("debug_in_prompt") or []:
        by_name.setdefault(item.get("name"), item)
    resolved = []
    missing = []
    for raw in locations:
        if not isinstance(raw, dict):
            continue
        path = str(raw.get("path") or "").replace("\\", "/")
        name = str(raw.get("function") or raw.get("name") or "")
        if not name:
            continue
        key = f"{path}:{name}" if path else ""
        item = available.get(key) or by_name.get(name)
        reason = str(raw.get("reason") or "").strip()
        if item and item.get("body"):
            resolved.append({
                "path": item.get("path") or path,
                "function": item.get("name") or name,
                "body": item["body"],
                "reason": reason,
            })
        else:
            missing.append((key or name, reason))
    source_dir = state.get("source_dir")
    if missing and source_dir and Path(source_dir).is_dir():
        symbols = scan_source(Path(source_dir))
        reasons = {token: reason for token, reason in missing}
        for item in lookup_bodies(Path(source_dir), symbols, [token for token, _reason in missing]):
            key = f"{item.get('path')}:{item.get('function')}"
            item["reason"] = reasons.get(key) or reasons.get(item.get("function") or "") or ""
            resolved.append(item)
    return resolved


def _mock_action(state: dict) -> dict:
    catalog = state.get("symbol_catalog") or ""
    target = _first_catalog_target(catalog, advisory_only=True) or _first_catalog_target(catalog, advisory_only=False)
    in_prompt = {item.get("key") for item in state.get("debug_in_prompt") or []}
    if target and target not in in_prompt:
        return {
            "action": "lookup",
            "request": [target],
            "drop": [],
            "reason": "the advisory names this function",
        }
    if target:
        path, name = target.rsplit(":", 1)
        return {
            "action": "located",
            "locations": [{
                "path": path,
                "function": name,
                "reason": (
                    "The loaded body returns its input unchanged, so a path in that input "
                    "is used without a check and produces the path escape described by the advisory."
                ),
            }],
        }
    return {"action": "cannot_locate"}


def _first_catalog_target(catalog: str, *, advisory_only: bool) -> str | None:
    for line in catalog.splitlines():
        if ":" not in line:
            continue
        path, names = line.split(":", 1)
        path = path.strip()
        for part in names.split(","):
            raw = part.strip()
            if not raw:
                continue
            if advisory_only and "[advisory]" not in raw:
                continue
            name = raw.replace("[advisory]", "").replace("[export]", "").strip()
            if name:
                return f"{path}:{name}"
    return None


def _empty_usage() -> dict:
    return {
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
        "cost": 0.0,
    }


def _openrouter_action(state: dict, messages: list[dict[str, str]]) -> tuple[dict, float, dict]:
    api_key = os.getenv("OPENROUTER_API_KEY")
    model_name = state.get("model_name") or "anthropic/claude-sonnet-5"
    if not api_key:
        logger.warning("debugger: OPENROUTER_API_KEY is not set")
        return {"action": "cannot_locate"}, 0.0, _empty_usage()
    client = OpenAI(
        api_key=api_key,
        base_url=os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL),
        timeout=120.0,
    )
    try:
        response = client.chat.completions.create(
            model=model_name,
            temperature=0,
            max_tokens=DEBUG_MAX_TOKENS,
            response_format={"type": "json_object"},
            extra_body={"reasoning": {"enabled": False, "exclude": True}},
            messages=messages,
        )
    except Exception as exc:
        message = f"debugger: OpenRouter request failed: {type(exc).__name__}: {exc!r}"
        record_request(state, node="debugger", call="locate", model=model_name, error=message)
        logger.warning(message)
        return {"action": "cannot_locate"}, 0.0, _empty_usage()
    record_request(state, node="debugger", call="locate", model=model_name, response=response)
    content = ""
    choices = getattr(response, "choices", None) or []
    if choices and getattr(choices[0], "message", None) is not None:
        content = choices[0].message.content or ""
    usage = response_usage(response)
    return _parse_action(content), response_cost(response), usage


def _parse_action(content: str) -> dict:
    text = content.strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        fenced = re_search_json(text)
        if fenced is None:
            return {"action": "cannot_locate"}
        payload = fenced
    if not isinstance(payload, dict):
        return {"action": "cannot_locate"}
    action = payload.get("action")
    if action == "lookup":
        return {
            "action": "lookup",
            "request": payload.get("request") if isinstance(payload.get("request"), list) else [],
            "drop": payload.get("drop") if isinstance(payload.get("drop"), list) else [],
            "reason": _reason_text(payload.get("reason")),
        }
    if action == "located":
        locations = payload.get("locations")
        return {
            "action": "located",
            "locations": _locations_with_reasons(locations if isinstance(locations, list) else []),
        }
    return {"action": "cannot_locate"}


def _located_explains(action: dict, state: dict) -> bool:
    """A located result must explain behavior from bodies that were actually loaded."""
    locations = action.get("locations") or []
    if not isinstance(locations, list) or not locations:
        return False
    loaded = {
        item.get("key")
        for item in state.get("debug_in_prompt") or []
        if item.get("body") and item.get("key")
    }
    loaded_names = {
        item.get("name")
        for item in state.get("debug_in_prompt") or []
        if item.get("body") and item.get("name")
    }
    for raw in locations:
        if not isinstance(raw, dict):
            return False
        name = str(raw.get("function") or raw.get("name") or "")
        path = str(raw.get("path") or "").replace("\\", "/")
        key = f"{path}:{name}" if path and name else ""
        if key not in loaded and name not in loaded_names:
            return False
        reason = _reason_text(raw.get("reason"))
        if len(reason) < 40:
            return False
    return True


def _reason_text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _locations_with_reasons(locations: list) -> list[dict]:
    cleaned = []
    for raw in locations:
        if not isinstance(raw, dict):
            continue
        cleaned.append({**raw, "reason": _reason_text(raw.get("reason"))})
    return cleaned


def re_search_json(text: str) -> dict | None:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _prompt_chars(messages: list[dict[str, str]]) -> int:
    return sum(len(message.get("content") or "") for message in messages)
