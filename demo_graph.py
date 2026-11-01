"""
demo_graph.py
=============
LangGraph graph for the local demo UIs (registered as ``demo`` in langgraph.json).

It runs the same pipeline nodes as graph.py and leaves their logic unchanged.
On top of that it:

* accepts input either as form fields (``package_name``, ``package_version``,
  ``vulnerability_id``, ``model_name``) or as a chat message such as
  ``jszip@3.7.1 GHSA-36fh-84j7-cv5h codex``;
* pins the requested vulnerability, like ``test_local_pipeline.py --vulnerability-id``;
* after every step, appends a short summary to ``messages`` (for chat UIs) and
  to ``progress`` (for the progress-page UI).

Nothing added here is visible to the model: summaries are written after each
step and patch_generation never reads ``messages`` or ``progress``.
"""

from __future__ import annotations

import operator
import os
import re
import time
from typing import Annotated, Any, Callable

from langchain_core.messages import AIMessage, AnyMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from adversarial_evaluation import adversarial_evaluation
from graph import increment_retry, route_after_classification, route_after_patch_generation
from maintainer_eval import maintainer_eval
from og_patch_resolution import og_patch_resolution
from package_input import package_input
from patch_application import patch_application
from patch_generation import patch_generation
from patch_scoring import patch_scoring
from patch_validation import patch_validation
from state import GraphState
from vulnerability_detection import vulnerability_detection
from vulnerability_rescan import vulnerability_rescan


MODEL_ALIASES = {
    "codex": "openai/gpt-5.3-codex",
    "gpt": "openai/gpt-5.3-codex",
    "sonnet": "anthropic/claude-sonnet-5",
    "claude": "anthropic/claude-sonnet-5",
}
PACKAGE_PATTERN = re.compile(r"(@?[A-Za-z0-9][\w.-]*(?:/[\w.-]+)?)@(\d[\w.+-]*)")
ADVISORY_PATTERN = re.compile(r"\b(GHSA(?:-[a-z0-9]{4}){3}|CVE-\d{4}-\d+)\b", re.IGNORECASE)
MAX_DIFF_CHARS = 4_000
USAGE = (
    "Send `package@version`, optionally followed by an advisory ID and a model, e.g.\n\n"
    "`jszip@3.7.1 GHSA-36fh-84j7-cv5h codex`\n\n"
    "Models: `codex`, `sonnet`, or any OpenRouter model ID such as `anthropic/claude-sonnet-5`."
)


class DemoState(GraphState, total=False):
    messages: Annotated[list[AnyMessage], add_messages]
    progress: Annotated[list[dict[str, Any]], operator.add]
    vulnerability_id: str | None
    input_error: str | None


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

def _message_text(message: Any) -> str:
    content = message.get("content") if isinstance(message, dict) else getattr(message, "content", "")
    if isinstance(content, list):  # multi-part content from chat UIs
        return " ".join(part.get("text", "") for part in content if isinstance(part, dict))
    return str(content or "")


def _parse_request(text: str) -> dict[str, Any]:
    package = PACKAGE_PATTERN.search(text)
    if not package:
        return {}
    request: dict[str, Any] = {"package_name": package.group(1), "package_version": package.group(2)}
    advisory = ADVISORY_PATTERN.search(text)
    if advisory:
        request["vulnerability_id"] = advisory.group(1)
    rest = (text[:package.start()] + " " + text[package.end():]).split()
    for token in rest:
        lowered = token.lower().strip(",.")
        if lowered in MODEL_ALIASES:
            request["model_name"] = MODEL_ALIASES[lowered]
        elif "/" in lowered and not ADVISORY_PATTERN.fullmatch(token):
            request["model_name"] = token.strip(",.")
    return request


def demo_input(state: DemoState) -> dict:
    """Fill run settings from form fields, or from the latest chat message."""
    request: dict[str, Any] = {}
    if not (state.get("package_name") and state.get("package_version")):
        human = [m for m in state.get("messages") or [] if getattr(m, "type", None) == "human"]
        request = _parse_request(_message_text(human[-1])) if human else {}
        if not request:
            error = "I couldn't find a package and version in that message."
            return {"input_error": error, "messages": [AIMessage(content=f"{error}\n\n{USAGE}")]}

    settings = {
        "package_name": state.get("package_name") or request.get("package_name"),
        "package_version": state.get("package_version") or request.get("package_version"),
        "vulnerability_id": state.get("vulnerability_id") or request.get("vulnerability_id"),
        "model_provider": state.get("model_provider") or os.getenv("MODEL_PROVIDER", "openrouter"),
        "model_name": state.get("model_name") or request.get("model_name") or os.getenv("MODEL_NAME"),
        "patch_scope": state.get("patch_scope") or "single",
        "retry_count": 0,
        "max_retries": int(state.get("max_retries") or os.getenv("MAX_RETRIES", "0")),
        "errors": [],
        "input_error": None,
    }
    target = settings["vulnerability_id"] or "the first detected vulnerability"
    summary = (
        f"Patching **{settings['package_name']}@{settings['package_version']}**, "
        f"target: {target}, model: `{settings['model_name']}`"
    )
    return {
        **settings,
        "messages": [AIMessage(content=f"▶️ {summary}")],
        "progress": [{"step": "demo_input", "title": "Run settings", "summary": summary, "seconds": 0.0}],
    }


def route_after_input(state: DemoState) -> str:
    return "end" if state.get("input_error") else "continue"


# ---------------------------------------------------------------------------
# Step summaries (written after each step; never shown to the model)
# ---------------------------------------------------------------------------

def _select_vulnerability(state: DemoState, result: dict) -> dict:
    """Pin the requested advisory, like test_local_pipeline --vulnerability-id."""
    requested = (state.get("vulnerability_id") or "").casefold()
    found = result.get("current_vulnerabilities") or []
    if not requested or not found:
        return result
    match = next(
        (v for v in found if requested in {str(i).casefold() for i in [v.get("id"), *(v.get("aliases") or [])] if i}),
        None,
    )
    return {**result, "current_vulnerabilities": [match] if match else []}


def _summary(step: str, state: dict) -> str:
    if step == "package_input_node":
        if state.get("source_dir"):
            return f"Downloaded and unpacked {state['package_name']}@{state['package_version']}."
        return f"Could not download the package: {'; '.join(state.get('errors') or []) or 'unknown error'}"
    if step == "vulnerability_detection_node":
        selected = state.get("current_vulnerabilities") or []
        if not selected:
            requested = state.get("vulnerability_id")
            return f"Requested advisory {requested} was not detected." if requested else "No vulnerability detected."
        v = selected[0]
        return (
            f"Target: **{v.get('id')}** ({v.get('severity')}): {v.get('description')}. "
            f"Fixed in {v.get('fixed_version') or 'no released version'}."
        )
    if step == "og_patch_resolution_node":
        key = state.get("answer_key") or {}
        commits = ", ".join(c.get("sha", "")[:7] for c in key.get("commit_refs") or []) or "none linked"
        return f"Maintainer fix: {key.get('status')} (commits: {commits}). Kept hidden from the model."
    if step == "patch_generation_node":
        if state.get("generation_status") == "failed":
            return f"No patch produced: {state.get('generation_error')}"
        patch = state.get("current_patch") or {}
        diff = (patch.get("diff") or "")[:MAX_DIFF_CHARS]
        files = ", ".join(patch.get("target_files") or []) or "unknown files"
        return f"`{patch.get('model_used')}` patched {files}:\n\n```diff\n{diff}\n```"
    if step == "patch_application_node":
        v = state.get("validation") or {}
        tick = lambda ok: "✅" if ok else "❌"  # noqa: E731
        return f"Sandbox: build {tick(v.get('build_succeeded'))}, tests / load check {tick(v.get('tests_passed'))}."
    if step == "vulnerability_rescan_node":
        remaining = len(state.get("remaining_vulnerabilities") or [])
        return f"Version-based rescan still reports {remaining} finding(s); expected, since the version number is unchanged."
    if step == "adversarial_evaluation_node":
        e = state.get("adversarial_evaluation") or {}
        return f"`{e.get('evaluator_model')}` review: genuine fix = **{e.get('genuine_fix')}**. {(e.get('reasoning') or '')[:400]}"
    if step == "patch_validation_node":
        verdict = "✅ **PASS**" if state.get("classification") == "pass" else "❌ **FAIL**"
        saved = f"saved as {state['mongo_id']}" if state.get("mongo_id") else "not saved (MongoDB unavailable)"
        return f"{verdict}: {state.get('classification_reason')} ({saved})"
    if step == "patch_scoring_node":
        s = state.get("patch_score") or {}
        return f"Vs maintainer fix: location {s.get('location')}, strategy {s.get('strategy')}, completeness {s.get('completeness')}."
    if step == "maintainer_eval_node":
        m = state.get("maintainer_eval") or {}
        return f"Maintainer-fix comparison: **{m.get('verdict')}**. {(m.get('summary') or '')[:500]}"
    if step == "increment_retry":
        return f"Retrying (attempt {state.get('retry_count', 0) + 1})."
    return "Done."


STEP_TITLES = {
    "package_input_node": "📦 Package input",
    "vulnerability_detection_node": "🔍 Vulnerability detection",
    "og_patch_resolution_node": "📚 Maintainer fix lookup",
    "patch_generation_node": "🤖 Patch generation",
    "patch_application_node": "🐳 Sandbox build",
    "vulnerability_rescan_node": "🔁 Rescan",
    "adversarial_evaluation_node": "🧑‍⚖️ Independent review",
    "patch_validation_node": "🏁 Validation",
    "patch_scoring_node": "📐 Scoring",
    "maintainer_eval_node": "📝 Maintainer comparison",
    "increment_retry": "↩️ Retry",
}


def _with_progress(step: str, node: Callable[[dict], dict]) -> Callable[[DemoState], dict]:
    """Run *node* unchanged, then append its summary to messages and progress."""

    def run(state: DemoState) -> dict:
        started = time.monotonic()
        result = node(state) or {}
        if step == "vulnerability_detection_node":
            result = _select_vulnerability(state, result)
        seconds = round(time.monotonic() - started, 1)
        summary = _summary(step, {**state, **result})
        title = STEP_TITLES[step]
        return {
            **result,
            "messages": [AIMessage(content=f"{title} ({seconds:.0f}s)\n\n{summary}")],
            "progress": [{"step": step, "title": title, "summary": summary, "seconds": seconds}],
        }

    return run


def route_after_detection(state: DemoState) -> str:
    return "continue" if state.get("current_vulnerabilities") and state.get("source_dir") else "end"


# ---------------------------------------------------------------------------
# Graph (same topology as graph.py, plus input parsing and an early exit)
# ---------------------------------------------------------------------------

builder = StateGraph(DemoState)
builder.add_node("demo_input", demo_input)
for name, fn in [
    ("package_input_node", package_input),
    ("vulnerability_detection_node", vulnerability_detection),
    ("og_patch_resolution_node", og_patch_resolution),
    ("patch_generation_node", patch_generation),
    ("patch_application_node", patch_application),
    ("vulnerability_rescan_node", vulnerability_rescan),
    ("adversarial_evaluation_node", adversarial_evaluation),
    ("patch_validation_node", patch_validation),
    ("patch_scoring_node", patch_scoring),
    ("maintainer_eval_node", maintainer_eval),
    ("increment_retry", increment_retry),
]:
    builder.add_node(name, _with_progress(name, fn))

builder.add_edge(START, "demo_input")
builder.add_conditional_edges("demo_input", route_after_input, {"continue": "package_input_node", "end": END})
builder.add_edge("package_input_node", "vulnerability_detection_node")
builder.add_conditional_edges(
    "vulnerability_detection_node", route_after_detection, {"continue": "og_patch_resolution_node", "end": END}
)
builder.add_edge("og_patch_resolution_node", "patch_generation_node")
builder.add_conditional_edges(
    "patch_generation_node",
    route_after_patch_generation,
    {"application": "patch_application_node", "validation": "patch_validation_node"},
)
builder.add_edge("patch_application_node", "vulnerability_rescan_node")
builder.add_edge("vulnerability_rescan_node", "adversarial_evaluation_node")
builder.add_edge("adversarial_evaluation_node", "patch_validation_node")
builder.add_edge("patch_validation_node", "patch_scoring_node")
builder.add_conditional_edges(
    "patch_scoring_node", route_after_classification, {"retry": "increment_retry", "eval": "maintainer_eval_node"}
)
builder.add_edge("increment_retry", "patch_generation_node")
builder.add_edge("maintainer_eval_node", END)

graph = builder.compile()
