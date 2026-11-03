"""Debugger loop: advisory and catalog stay in the first user message.

Later turns resend that message and replace only the current function bodies.
No provider prompt cache is requested. Dropped bodies leave the prompt and
remain requestable.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from cost_log import record_request
from run_cost import response_cost
from symbol_index import MAX_BODY_LOADS, lookup_bodies, scan_source

load_dotenv()
logger = logging.getLogger(__name__)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEBUG_MAX_TOKENS = 2_000
MAX_DEBUG_ROUNDS = 4
MAX_DEBUG_PROMPT_CHARS = 100_000
_TERMINAL = {"located", "cannot_locate", "capped"}

_SYSTEM = (
    "You locate vulnerable functions. You are not told the package name or version. "
    "Use only the advisory and the catalog in the conversation. "
    "Reply with one JSON object and nothing else.\n"
    'Lookup: {"action":"lookup","request":["file.js:name"],"drop":["file.js:other"]}\n'
    'Found: {"action":"located","locations":[{"path":"file.js","function":"name"}]}\n'
    'Give up: {"action":"cannot_locate"}\n'
    "request names at most 3 functions. drop removes bodies that are unrelated. "
    "A dropped name stays in the catalog and may be requested again. "
    "The catalog message is the list of files and functions you can ask for."
)


def route_after_index(state: dict) -> str:
    if state.get("debug_status") in _TERMINAL:
        return "generation"
    return "debugger"


def route_after_debugger(state: dict) -> str:
    if state.get("debug_request"):
        return "index"
    return "generation"


def debugger_node(state: dict) -> dict:
    """Ask the model whether the current bodies are enough."""
    if state.get("debug_status") in _TERMINAL:
        return {"debug_request": None}

    rounds = int(state.get("debug_rounds") or 0)
    loads = int(state.get("debug_body_loads") or 0)
    if rounds >= MAX_DEBUG_ROUNDS or loads >= MAX_BODY_LOADS:
        return {"debug_status": "capped", "debug_request": None, "debug_rounds": rounds}

    messages = build_messages(state)
    if _prompt_chars(messages) > MAX_DEBUG_PROMPT_CHARS:
        return {"debug_status": "capped", "debug_request": None, "debug_rounds": rounds}

    run_id = state.get("run_attempt_id") or f"{state.get('package_name') or 'package'}-{uuid.uuid4()}"
    provider = state.get("model_provider", "mock")
    if provider == "mock":
        action, cost = _mock_action(state), 0.0
    elif provider == "openrouter":
        action, cost = _openrouter_action({**state, "run_attempt_id": run_id}, messages)
    else:
        action, cost = {"action": "cannot_locate"}, 0.0

    spent = float(state.get("run_cost") or 0) + cost
    actions = list(state.get("debug_actions") or [])
    actions.append(action)
    base = {
        "run_attempt_id": run_id,
        "run_cost": spent,
        "debug_actions": actions,
        "debug_rounds": rounds + 1,
        "debug_request": None,
    }
    kind = action.get("action")
    if kind == "lookup":
        return {
            **base,
            "debug_status": "running",
            "debug_request": {
                "request": [str(item) for item in action.get("request") or [] if str(item).strip()],
                "drop": [str(item) for item in action.get("drop") or [] if str(item).strip()],
            },
        }
    if kind == "located":
        return {
            **base,
            "debug_status": "located",
            "debug_locations": _locations_with_bodies(state, action.get("locations") or []),
        }
    return {**base, "debug_status": "cannot_locate", "debug_locations": []}


def build_messages(state: dict) -> list[dict[str, str]]:
    """Advisory and catalog occupy a stable user message. Bodies are the next one."""
    findings = state.get("current_vulnerabilities") or state.get("vulnerabilities") or []
    finding = findings[0] if findings else {}
    advisory = "\n".join([
        "Advisory:",
        f"id: {finding.get('id', 'unknown')}",
        f"severity: {finding.get('severity', 'unknown')}",
        f"description: {finding.get('description', '')}",
        "",
        "Catalog:",
        state.get("symbol_catalog") or "(no functions found)",
    ])
    return [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": advisory},
        {"role": "user", "content": _body_message(state)},
    ]


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
    return (
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
        if item and item.get("body"):
            resolved.append({
                "path": item.get("path") or path,
                "function": item.get("name") or name,
                "body": item["body"],
            })
        else:
            missing.append(key or name)
    source_dir = state.get("source_dir")
    if missing and source_dir and Path(source_dir).is_dir():
        symbols = scan_source(Path(source_dir))
        resolved.extend(lookup_bodies(Path(source_dir), symbols, missing))
    return resolved


def _mock_action(state: dict) -> dict:
    catalog = state.get("symbol_catalog") or ""
    target = _first_catalog_target(catalog, advisory_only=True) or _first_catalog_target(catalog, advisory_only=False)
    in_prompt = {item.get("key") for item in state.get("debug_in_prompt") or []}
    if target and target not in in_prompt:
        return {"action": "lookup", "request": [target], "drop": []}
    if target:
        path, name = target.rsplit(":", 1)
        return {"action": "located", "locations": [{"path": path, "function": name}]}
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


def _openrouter_action(state: dict, messages: list[dict[str, str]]) -> tuple[dict, float]:
    api_key = os.getenv("OPENROUTER_API_KEY")
    model_name = state.get("model_name") or "anthropic/claude-sonnet-5"
    if not api_key:
        logger.warning("debugger: OPENROUTER_API_KEY is not set")
        return {"action": "cannot_locate"}, 0.0
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
        return {"action": "cannot_locate"}, 0.0
    record_request(state, node="debugger", call="locate", model=model_name, response=response)
    content = ""
    choices = getattr(response, "choices", None) or []
    if choices and getattr(choices[0], "message", None) is not None:
        content = choices[0].message.content or ""
    return _parse_action(content), response_cost(response)


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
        }
    if action == "located":
        locations = payload.get("locations")
        return {"action": "located", "locations": locations if isinstance(locations, list) else []}
    return {"action": "cannot_locate"}


def re_search_json(text: str) -> dict | None:
    import re
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
