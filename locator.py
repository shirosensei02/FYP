"""Locate vulnerable code on the package graph.

Each turn asks the model for one action. A tool action is handed to
repo_graph_node and the result comes back on the next turn. The finished
action is the location list from prompts/locator.txt: path, line, class, and
function, ordered by importance. Two samples are merged by summed reciprocal
rank of that order, and the merged functions are written for patch generation.
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
from repo_graph import ensure_repo_graph, retrieve_entity
from run_cost import response_cost

load_dotenv()
logger = logging.getLogger(__name__)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
LOCATOR_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "locator.txt"
LOCATOR_SAMPLES = 2
MAX_LOCATOR_ROUNDS = 8
MAX_PROMPT_CHARS = 48_000
LOCATOR_COST_CAP = 2.0
TOP_LOCATIONS = 10
_TERMINAL = {"ranked", "cannot_locate", "capped"}
_STOPWORDS = {
    "with", "from", "that", "this", "into", "when", "where", "allow", "allows",
    "vulnerability", "vulnerable", "package", "version", "security", "through",
    "unchanged", "input", "function",
}

_TOOL_CONTRACT = """
## Tools
The package is JavaScript. A function id is file_path:QualifiedName, for example lib/client.js:Client.query.
While you are still on the steps above, reply with one JSON object that calls one tool. Do not locate yet.
SearchEntity finds entities by keyword. detail is fold, preview, or full.
{"action":"tool","tool":"SearchEntity","arguments":{"keywords":["query"],"detail":"preview"}}
TraverseGraph walks contain, import, invoke, or inherit edges. direction is out, in, or both.
{"action":"tool","tool":"TraverseGraph","arguments":{"start_ids":["lib/client.js:Client.query"],"direction":"out","hops":1,"entity_types":["function"],"relation_types":["invoke"]}}
RetrieveEntity returns the full body of an entity. Locate only after a retrieved body shows the vulnerable behavior. A matching name is not enough.
{"action":"tool","tool":"RetrieveEntity","arguments":{"entity_ids":["lib/client.js:Client.query"]}}

## Final locations
When the steps are done, reply with one JSON object and nothing else. Do not use a Markdown fence.
Order the locations by importance, most important first, and include about 5.
Use the same fields as the examples above: path, line, class, and function. Omit class when there is no class. function may be a QualifiedName such as Client.query.
{"action":"locate","locations":[{"path":"lib/client.js","line":10,"class":"Client","function":"query"}]}
"""


def route_after_locator(state: dict) -> str:
    """A tool request goes to the graph. Another sample stays here. A ranking proceeds."""
    if state.get("graph_request"):
        return "repo_graph"
    if state.get("locate_status") == "running":
        return "locator"
    return "generation"


def locator_node(state: dict) -> dict:
    """Prompt for the next tool or fold a finished pair of rankings."""
    if state.get("locate_status") in _TERMINAL:
        return {"graph_request": None}

    if not state.get("repo_graph_ready"):
        return {
            "locate_status": "cannot_locate",
            "graph_request": None,
            "debug_locations": [],
            "located_entities": [],
        }

    sample = int(state.get("locate_sample") or 0)
    rounds = int(state.get("locate_rounds") or 0)
    samples = list(state.get("locate_samples") or [])
    trace = [dict(item) for item in (state.get("locate_trace") or [])]
    result = state.get("graph_result")
    if result and trace and trace[-1].get("kind") == "tool_call" and "result" not in trace[-1]:
        trace[-1]["result"] = result

    if rounds >= MAX_LOCATOR_ROUNDS or float(state.get("run_cost") or 0) > LOCATOR_COST_CAP:
        return _advance_sample(state, samples, sample, [], capped=True)

    provider = state.get("model_provider", "mock")
    run_id = state.get("run_attempt_id") or f"{state.get('package_name') or 'package'}-{uuid.uuid4()}"
    if provider == "mock":
        action, cost = _mock_action(state, trace), 0.0
    elif provider == "openrouter":
        action, cost = _openrouter_action({**state, "run_attempt_id": run_id}, _messages(state, trace))
    else:
        action, cost = {"action": "locate", "locations": []}, 0.0

    spent = float(state.get("run_cost") or 0) + cost
    if action.get("action") == "tool":
        trace.append({
            "kind": "tool_call",
            "tool": action.get("tool"),
            "arguments": action.get("arguments") or {},
        })
        return {
            "run_attempt_id": run_id,
            "run_cost": spent,
            "locate_status": "running",
            "locate_sample": sample,
            "locate_rounds": rounds + 1,
            "locate_samples": samples,
            "locate_trace": trace,
            "graph_request": {
                "caller": "locator",
                "tool": action.get("tool"),
                "arguments": action.get("arguments") or {},
            },
            "graph_result": None,
        }

    locations = action.get("locations") if isinstance(action.get("locations"), list) else []
    return _advance_sample(state, samples, sample, locations, run_id=run_id, spent=spent)


def _advance_sample(state: dict, samples: list, sample: int, locations: list, capped: bool = False, run_id: str | None = None, spent: float | None = None) -> dict:
    samples = list(samples)
    samples.append(_clean_locations(locations))
    base = {
        "run_attempt_id": run_id or state.get("run_attempt_id"),
        "locate_samples": samples,
        "locate_trace": [],
        "locate_rounds": 0,
        "graph_request": None,
        "graph_result": None,
    }
    if spent is not None:
        base["run_cost"] = spent
    if sample + 1 < LOCATOR_SAMPLES and not capped:
        return {
            **base,
            "locate_status": "running",
            "locate_sample": sample + 1,
        }
    merged = _merge_rankings(samples)
    locations = _locations_with_bodies(state, merged)
    status = "capped" if capped and not locations else ("ranked" if locations else "cannot_locate")
    return {
        **base,
        "locate_status": status,
        "locate_sample": sample,
        "located_entities": merged,
        "debug_locations": locations,
        "localized_files": list(dict.fromkeys(item["path"] for item in locations if item.get("path"))),
    }


def _clean_locations(locations: list) -> list[dict]:
    """List order is importance. The first location is rank 1."""
    cleaned = []
    for index, raw in enumerate(locations, start=1):
        if isinstance(raw, str):
            raw = {"id": raw}
        if not isinstance(raw, dict):
            continue
        path = str(raw.get("path") or "").replace("\\", "/").strip()
        function = str(raw.get("function") or raw.get("name") or "").strip()
        class_name = str(raw.get("class") or raw.get("class_name") or "").strip()
        line = _first_line(raw.get("line") if raw.get("line") is not None else raw.get("lines"))
        entity_id = str(raw.get("id") or raw.get("entity_id") or "").replace("\\", "/").strip()
        if not entity_id:
            entity_id = _compose_id(path, class_name, function)
        if not entity_id:
            continue
        try:
            rank = int(raw.get("rank") or index)
        except (TypeError, ValueError):
            rank = index
        cleaned.append({
            "id": entity_id,
            "rank": rank if rank > 0 else index,
            "reason": str(raw.get("reason") or "").strip(),
            "path": path,
            "line": line,
            "class": class_name,
            "function": function,
        })
    return cleaned


def _compose_id(path: str, class_name: str, function: str) -> str:
    if function and "." in function:
        qualified = function
    elif class_name and function:
        qualified = f"{class_name}.{function}"
    else:
        qualified = function or class_name
    if path and qualified:
        return f"{path}:{qualified}"
    return path or qualified


def _first_line(value) -> int | None:
    if isinstance(value, list):
        value = value[0] if value else None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _merge_rankings(samples: list) -> list[dict]:
    """Sum 1/rank across samples. A function ranked first twice outranks a single mention."""
    scores: dict[str, float] = {}
    details: dict[str, dict] = {}
    for sample in samples:
        for item in sample or []:
            entity_id = item.get("id")
            if not entity_id:
                continue
            scores[entity_id] = scores.get(entity_id, 0.0) + 1.0 / int(item.get("rank") or 1)
            if entity_id not in details:
                details[entity_id] = item
    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    merged = []
    for entity_id, score in ranked[:TOP_LOCATIONS]:
        item = dict(details[entity_id])
        item["id"] = entity_id
        item["score"] = score
        merged.append(item)
    return merged


def _locations_with_bodies(state: dict, ranked: list[dict]) -> list[dict]:
    source_dir = state.get("source_dir")
    if not source_dir or not ranked:
        return []
    graph = ensure_repo_graph(
        Path(source_dir),
        state.get("package_name") or "package",
        state.get("package_version") or "unknown",
    )
    bodies = {
        item.get("id"): item
        for item in retrieve_entity(graph, [item["id"] for item in ranked]).get("entities") or []
    }
    resolved = []
    for item in ranked:
        entity = bodies.get(item["id"])
        if not entity or not entity.get("code") or entity.get("type") not in {"function", "class"}:
            continue
        resolved.append({
            "id": item["id"],
            "path": entity.get("path") or item.get("path") or "",
            "line": item.get("line"),
            "class": item.get("class") or "",
            "function": entity.get("name") or item.get("function") or "",
            "body": entity.get("code") or "",
            "reason": item.get("reason") or "",
            "score": item.get("score"),
        })
    return resolved


def _system_prompt(state: dict) -> str:
    """Chain-of-thought steps from locator.txt, plus the tool and final-location contract."""
    package = state.get("package_name") or "package"
    if LOCATOR_PROMPT_PATH.is_file():
        steps = LOCATOR_PROMPT_PATH.read_text(encoding="utf-8")
    else:
        steps = "Localize the files, classes, functions, and lines that need to change."
    steps = steps.replace("{{package_name}}", str(package))
    return f"{steps.rstrip()}\n{_TOOL_CONTRACT}"


def _messages(state: dict, trace: list[dict]) -> list[dict[str, str]]:
    findings = state.get("current_vulnerabilities") or state.get("vulnerabilities") or []
    finding = findings[0] if findings else {}
    advisory = "\n".join([
        "GitHub problem description:",
        f"id: {finding.get('id', 'unknown')}",
        f"severity: {finding.get('severity', 'unknown')}",
        f"description: {finding.get('description', '')}",
        f"summary: {_summary(state)}",
        "",
        f"Graph: {state.get('repo_graph_summary') or '(empty)'}",
        "",
        "Tool trace:",
        _render_trace(trace),
    ])
    return [
        {"role": "system", "content": _system_prompt(state)},
        {"role": "user", "content": advisory[:MAX_PROMPT_CHARS]},
    ]


def _summary(state: dict) -> str:
    answer = state.get("answer_key") or {}
    summary = answer.get("summary")
    if not isinstance(summary, str):
        return ""
    return summary.strip()[:500]


def _render_trace(trace: list[dict]) -> str:
    if not trace:
        return "none"
    lines = []
    for item in trace:
        result = item.get("result")
        rendered = json.dumps(result, ensure_ascii=False)[:4000] if result else "pending"
        lines.append(
            f"{item.get('tool')} {json.dumps(item.get('arguments') or {}, ensure_ascii=False)}\n{rendered}"
        )
    return "\n\n".join(lines)[:MAX_PROMPT_CHARS]


def _mock_action(state: dict, trace: list[dict]) -> dict:
    if trace and trace[-1].get("result") is not None:
        entities = (trace[-1].get("result") or {}).get("entities") or []
        functions = [item for item in entities if item.get("type") == "function"] or entities
        if not functions:
            return {"action": "locate", "locations": []}
        chosen = functions[0]
        return {
            "action": "locate",
            "locations": [{
                "path": chosen.get("path") or "",
                "line": 1,
                "class": "",
                "function": chosen.get("qualified") or chosen.get("name") or "",
                "id": chosen.get("id"),
                "reason": "The retrieved function is the one the advisory names, and its body performs that operation.",
            }],
        }
    return {
        "action": "tool",
        "tool": "SearchEntity",
        "arguments": {"keywords": _advisory_keywords(state), "detail": "preview"},
    }


def _advisory_keywords(state: dict) -> list[str]:
    findings = state.get("current_vulnerabilities") or state.get("vulnerabilities") or []
    finding = findings[0] if findings else {}
    text = f"{finding.get('description', '')} {_summary(state)}"
    keywords = []
    seen: set[str] = set()
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text):
        lowered = token.lower()
        if len(token) < 4 or lowered in _STOPWORDS or lowered in seen:
            continue
        seen.add(lowered)
        keywords.append(token)
        if len(keywords) >= 4:
            break
    return keywords or ["function"]


def _openrouter_action(state: dict, messages: list[dict[str, str]]) -> tuple[dict, float]:
    api_key = os.getenv("OPENROUTER_API_KEY")
    model_name = state.get("model_name") or "anthropic/claude-sonnet-5"
    if not api_key:
        logger.warning("locator: OPENROUTER_API_KEY is not set")
        return {"action": "locate", "locations": []}, 0.0
    client = OpenAI(
        api_key=api_key,
        base_url=os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL),
        timeout=120.0,
    )
    try:
        response = client.chat.completions.create(
            model=model_name,
            temperature=1,
            max_tokens=2_000,
            response_format={"type": "json_object"},
            extra_body={"reasoning": {"enabled": False, "exclude": True}},
            messages=messages,
        )
    except Exception as exc:
        message = f"locator: OpenRouter request failed: {type(exc).__name__}: {exc!r}"
        record_request(state, node="locator", call="locate", model=model_name, error=message)
        logger.warning(message)
        return {"action": "locate", "locations": []}, 0.0
    record_request(state, node="locator", call="locate", model=model_name, response=response)
    content = ""
    choices = getattr(response, "choices", None) or []
    if choices and getattr(choices[0], "message", None) is not None:
        content = choices[0].message.content or ""
    return _parse_action(content), response_cost(response)


def _parse_action(content: str) -> dict:
    text = content.strip()
    payload = _load_json_object(text)
    if isinstance(payload, dict):
        if payload.get("action") == "tool" and payload.get("tool") in {"SearchEntity", "TraverseGraph", "RetrieveEntity"}:
            arguments = payload.get("arguments") if isinstance(payload.get("arguments"), dict) else {}
            return {"action": "tool", "tool": payload["tool"], "arguments": arguments}
        if payload.get("action") in {"locate", "rank"} or isinstance(payload.get("locations"), list):
            locations = payload.get("locations")
            return {"action": "locate", "locations": locations if isinstance(locations, list) else []}
    located = _parse_location_text(text)
    if located:
        return {"action": "locate", "locations": located}
    return {"action": "locate", "locations": []}


def _load_json_object(text: str) -> dict | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match is None:
            return None
        try:
            payload = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return payload if isinstance(payload, dict) else None


def _parse_location_text(text: str) -> list[dict]:
    """Accept the fenced path / line / class / function block from locator.txt."""
    locations = []
    current = None
    for raw in text.splitlines():
        line = raw.strip().strip("`")
        if not line or line.lower().startswith("note:"):
            continue
        labeled = re.match(r"^(line|class|function):\s*(.*)$", line, re.IGNORECASE)
        if labeled:
            if current is None:
                continue
            key = labeled.group(1).lower()
            value = labeled.group(2).strip()
            if key == "line":
                current.setdefault("lines", []).append(value)
                if "line" not in current:
                    current["line"] = value
            else:
                current[key] = value
            continue
        if "/" in line or line.endswith((".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx", ".py")):
            if current:
                locations.append(current)
            current = {"path": line.replace("\\", "/")}
    if current:
        locations.append(current)
    return locations
