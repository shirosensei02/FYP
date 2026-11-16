"""
chat_graph.py
=============
Chat front end for the patch pipeline (registered as ``pipeline-chat`` in langgraph.json).

The pipeline itself is not redefined here: every node, edge and routing rule is
copied from the compiled graph in graph.py when this module loads, so the chat
always runs the current pipeline. On top of it the chat layer adds:

* reading package, version, advisory, and model from the chat, including across
  several messages when the first one is incomplete;
* starting the run only after a later message confirms the parsed fields
  (a normal chat turn, with no interrupt);
* running the targets one after another, each in a fresh pipeline state
  (built like batch_runner.py builds one), so nothing leaks between runs;
* pinning the requested advisory, like ``test_local_pipeline.py --vulnerability-id``;
* a chat message after each pipeline step and a comparison table at the end.

The pipeline nodes only ever see the per-target state (``run``); the chat
messages are written after each step and are never shown to the model.
"""

from __future__ import annotations

import os
import re
import time
from typing import Annotated, Any, Callable, TypedDict

from langchain_core.messages import AIMessage, AnyMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from batch_runner import _fresh_state
from graph import graph as pipeline_graph
from intake import ADVISORY_PATTERN, parse_prompt


MODEL_ALIASES = {
    "codex": "openai/gpt-5.3-codex",
    "gpt": "openai/gpt-5.3-codex",
    "sonnet": "anthropic/claude-sonnet-5",
    "claude": "anthropic/claude-sonnet-5",
}
MAX_TARGETS = 5
MAX_DIFF_CHARS = 4_000
USAGE = (
    "Send one or more targets as `package@version [advisory ID] [model]`, optionally followed by "
    "a short suspected issue and a maintainer commit URL, separated by commas or new lines, e.g.\n\n"
    "`jszip@3.7.1 GHSA-36fh-84j7-cv5h codex path traversal when loading a zip "
    "https://github.com/Stuk/jszip/commit/abcdef1`\n\n"
    "`jszip@3.7.1 GHSA-36fh-84j7-cv5h codex, tar-fs@3.0.8 GHSA-8cj5-5rvv-wf4v sonnet`\n\n"
    "A package name alone is enough to start: the reply names whatever is still missing "
    "(package name, package version, and model when `.env` has no `MODEL_NAME`). "
    "The advisory and the issue description are optional. "
    "Models: `codex`, `sonnet`, or any OpenRouter model ID such as `anthropic/claude-sonnet-5`. "
    "When the fields are filled in, reply `confirm` to start."
)
_FIELD_LABELS = {"version", "package", "advisory", "model"}
_PACKAGE_TOKEN = re.compile(r"^@?[A-Za-z0-9][\w.-]*(?:/[\w.-]+)?$")
_VERSION_TOKEN = re.compile(r"^\d+\.\d[\w.+-]*$")


class ChatState(TypedDict, total=False):
    messages: Annotated[list[AnyMessage], add_messages]
    targets: list[dict[str, Any]]
    target_index: int
    run: dict[str, Any]  # pipeline state of the current target (GraphState keys)
    results: list[dict[str, Any]]
    input_error: str | None
    phase: str  # collecting | awaiting_confirm | running | done


# ---------------------------------------------------------------------------
# Reading targets from the chat
# ---------------------------------------------------------------------------

def _message_text(message: Any) -> str:
    content = message.get("content") if isinstance(message, dict) else getattr(message, "content", "")
    if isinstance(content, list):  # multi-part content from chat UIs
        return " ".join(part.get("text", "") for part in content if isinstance(part, dict))
    return str(content or "")


def _parse_request(text: str) -> dict[str, Any]:
    draft = parse_prompt(text)
    if not draft["package_name"]:
        return {}
    request: dict[str, Any] = {
        "package_name": draft["package_name"],
        "package_version": draft["package_version"],
        "user_prompt": text.strip(),
    }
    if draft["vulnerability_id"]:
        request["vulnerability_id"] = draft["vulnerability_id"]
    if draft["suspected_issue"]:
        request["suspected_issue"] = draft["suspected_issue"]
    if draft["maintainer_commit_url"]:
        request["maintainer_commit_url"] = draft["maintainer_commit_url"]
    model = draft["model_name"].lower()
    if model in MODEL_ALIASES:
        request["model_name"] = MODEL_ALIASES[model]
    elif model:
        request["model_name"] = draft["model_name"]
    return request


def _parse_targets(text: str) -> list[dict[str, Any]]:
    """One target per comma/semicolon/line-separated segment that names ``package@version``.

    A target without a model uses the nearest model named before it, then the
    first model named anywhere in the message, then MODEL_NAME from .env.
    """
    targets = [request for segment in re.split(r"[,;\n]+", text) if (request := _parse_request(segment))]
    named = [target["model_name"] for target in targets if target.get("model_name")]
    fallback = named[0] if named else os.getenv("MODEL_NAME")
    previous = None
    for target in targets:
        previous = target.get("model_name") or previous
        target["model_name"] = previous or fallback
    return targets


def _is_confirm(text: str) -> bool:
    return text.strip().lower().strip(".!") in {"confirm", "yes"}


def _is_model_token(token: str) -> bool:
    lowered = token.lower().strip(",.")
    if lowered in MODEL_ALIASES:
        return True
    return "/" in lowered and not lowered.startswith(("http://", "https://", "@"))


def _stored_model(token: str) -> str:
    cleaned = token.strip(".,;")
    return MODEL_ALIASES.get(cleaned.lower(), cleaned)


def _bare_package_name(text: str) -> str:
    """A package named without `@version`: a scoped or hyphenated token, or the only word left."""
    draft = parse_prompt(text)
    raw = text.replace(draft["maintainer_commit_url"], " ") if draft["maintainer_commit_url"] else text
    candidates = []
    leftovers = []
    for token in (part.strip(",.;") for part in raw.split()):
        if not token or token.lower() in _FIELD_LABELS:
            continue
        if _VERSION_TOKEN.fullmatch(token) or ADVISORY_PATTERN.fullmatch(token) or _is_model_token(token):
            continue
        if token.startswith(("http://", "https://")):
            continue
        if _PACKAGE_TOKEN.fullmatch(token) and ("-" in token or "/" in token or token.startswith("@")):
            candidates.append(token)
        else:
            leftovers.append(token)
    if candidates:
        return candidates[0]
    plain = [token for token in leftovers if _PACKAGE_TOKEN.fullmatch(token)]
    if len(plain) == 1 and len(leftovers) == 1:
        return plain[0]
    return ""


def _bare_version(text: str) -> str:
    match = re.search(r"(?<!@)(?<![\w.])(\d+\.\d[\w.+-]*)", text)
    return match.group(1) if match else ""


def _remainder_issue(text: str, found: dict[str, Any]) -> str:
    """Words left after the fields this message already contributed."""
    structured = any(found.get(key) for key in (
        "package_name", "package_version", "vulnerability_id", "model_name", "maintainer_commit_url",
    ))
    if not structured:
        return text.strip()
    url = str(found.get("maintainer_commit_url") or "")
    raw = text.replace(url, " ") if url else text
    words = []
    for token in raw.split():
        cleaned = token.strip(",.;")
        if not cleaned:
            continue
        if cleaned == found.get("package_name") or cleaned.lower() in _FIELD_LABELS:
            continue
        if _VERSION_TOKEN.fullmatch(cleaned) or ADVISORY_PATTERN.fullmatch(cleaned) or _is_model_token(cleaned):
            continue
        if cleaned.startswith(("http://", "https://")):
            continue
        words.append(cleaned)
    if words and all(word.lower() in _FIELD_LABELS for word in words):
        return ""
    return " ".join(words).strip()


def _extract_fields(text: str) -> dict[str, Any]:
    """Fields actually present in one message. Empty fields are omitted so a later merge can keep them."""
    raw = str(text or "").strip()
    if not raw or _is_confirm(raw):
        return {}
    draft = parse_prompt(raw)
    found: dict[str, Any] = {}
    packaged = bool(draft["package_name"] and draft["package_version"])
    if packaged:
        found["package_name"] = draft["package_name"]
        found["package_version"] = draft["package_version"]
    else:
        name = _bare_package_name(raw)
        if name:
            found["package_name"] = name
        version = _bare_version(raw)
        if version:
            found["package_version"] = version
    if draft["vulnerability_id"]:
        found["vulnerability_id"] = draft["vulnerability_id"]
    if draft["maintainer_commit_url"]:
        found["maintainer_commit_url"] = draft["maintainer_commit_url"]
    if draft["model_name"]:
        found["model_name"] = _stored_model(draft["model_name"])
    issue = draft["suspected_issue"] if packaged else _remainder_issue(raw, found)
    if issue:
        found["suspected_issue"] = issue
    if not found:
        return {}
    found["user_prompt"] = raw
    return found


def _merge_target(base: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in new.items():
        if value:
            merged[key] = value
    prompts = []
    for prompt in (base.get("user_prompt"), new.get("user_prompt")):
        if prompt and prompt not in prompts:
            prompts.append(prompt)
    if prompts:
        merged["user_prompt"] = "\n".join(prompts)
    return merged


def _targets_from_message(text: str) -> list[dict[str, Any]]:
    """Targets named in this message. A segment with no package is folded into the previous one."""
    segments = [segment.strip() for segment in re.split(r"[,;\n]+", text) if segment.strip()]
    targets: list[dict[str, Any]] = []
    for segment in segments:
        fields = _extract_fields(segment)
        if fields.get("package_name") or fields.get("package_version"):
            targets.append(fields)
            continue
        extra = fields.get("vulnerability_id") or fields.get("model_name") or fields.get("maintainer_commit_url")
        if targets and (extra or fields.get("suspected_issue")):
            targets[-1] = _merge_target(targets[-1], fields)
        elif not targets and len(segments) == 1 and extra:
            targets.append(fields)
    return targets


def _combine(saved: list[dict[str, Any]], text: str) -> list[dict[str, Any]]:
    """Merge a follow-up into one saved draft. A different package, or several packages, replaces it."""
    if _is_confirm(text):
        return saved
    found = _targets_from_message(text)
    if not found:
        if len(saved) == 1 and text:
            issue = _remainder_issue(text, {})
            if issue:
                updated = dict(saved[0])
                updated["suspected_issue"] = issue
                updated["user_prompt"] = text
                return [updated]
        return saved
    if len(found) > 1 or not saved:
        return found
    new = found[0]
    if len(saved) != 1:
        # A version or advisory alone cannot be attached to one target in a batch.
        return found if new.get("package_name") else saved
    if new.get("package_name") and saved[0].get("package_name") and new["package_name"] != saved[0]["package_name"]:
        return found
    return [_merge_target(saved[0], new)]


def _fill_models(targets: list[dict[str, Any]]) -> None:
    named = [target["model_name"] for target in targets if target.get("model_name")]
    fallback = named[0] if named else os.getenv("MODEL_NAME") or ""
    previous = ""
    for target in targets:
        previous = target.get("model_name") or previous
        if not target.get("model_name"):
            target["model_name"] = previous or fallback


def _missing(target: dict[str, Any]) -> list[str]:
    missing = []
    if not str(target.get("package_name") or "").strip():
        missing.append("package name")
    if not str(target.get("package_version") or "").strip():
        missing.append("package version")
    if not str(target.get("model_name") or "").strip():
        missing.append("model")
    return missing


def _gap_lines(targets: list[dict[str, Any]]) -> list[str]:
    if not targets:
        return ["package name", "package version"]
    lines = []
    for target in targets:
        missing = _missing(target)
        if not missing:
            continue
        name = str(target.get("package_name") or "").strip()
        lines.append(f"{name}: {', '.join(missing)}" if name else ", ".join(missing))
    return lines


def _so_far(targets: list[dict[str, Any]]) -> str:
    rows = []
    for target in targets:
        bits = []
        if target.get("package_name"):
            bits.append(f"package: {target['package_name']}")
        if target.get("package_version"):
            bits.append(f"version: {target['package_version']}")
        if target.get("vulnerability_id"):
            bits.append(f"advisory: {target['vulnerability_id']}")
        if target.get("model_name"):
            bits.append(f"model: `{target['model_name']}`")
        if target.get("suspected_issue"):
            bits.append(f'suspected issue: "{target["suspected_issue"]}"')
        if target.get("maintainer_commit_url"):
            bits.append(f"maintainer patch: {target['maintainer_commit_url']}")
        if bits:
            rows.append("- " + "; ".join(bits))
    return "So far:\n" + "\n".join(rows) if rows else ""


def _missing_text(targets: list[dict[str, Any]], gaps: list[str], note: str) -> str:
    listed = "\n".join(f"- {gap}" for gap in gaps)
    so_far = _so_far(targets)
    extra = f"\n\n{so_far}" if so_far else ""
    usage = f"\n\n{USAGE}" if not targets else ""
    return f"Still need:\n{listed}{extra}{usage}{note}"


def _ready_text(targets: list[dict[str, Any]], note: str) -> str:
    blocks = []
    for index, target in enumerate(targets, start=1):
        prefix = f"{index}. " if len(targets) > 1 else ""
        issue = str(target.get("suspected_issue") or "").strip()
        commit = str(target.get("maintainer_commit_url") or "").strip()
        advisory = target.get("vulnerability_id") or "first detected advisory"
        blocks.append("\n".join([
            f"{prefix}**{target['package_name']}@{target['package_version']}**",
            f"advisory: {advisory}",
            f"model: `{target['model_name']}`",
            f'suspected issue: "{issue}"' if issue else "suspected issue: (none)",
            f"maintainer patch: {commit}" if commit else "maintainer patch: (none)",
        ]))
    heading = "1 package is ready." if len(targets) == 1 else f"{len(targets)} packages are ready."
    return f"{heading} Reply `confirm` to start, or send a correction.\n\n" + "\n\n".join(blocks) + note


def _starting_text(targets: list[dict[str, Any]]) -> str:
    names = ", ".join(f"**{t['package_name']}@{t['package_version']}**" for t in targets)
    if len(targets) == 1:
        return f"▶️ Starting {names}."
    return f"▶️ Starting {len(targets)} packages, one after another: {names}."


def chat_input(state: ChatState) -> dict:
    """Parse the newest message onto the saved draft, or start the run on confirm.

    The graph ends after asking for missing fields and after posting a complete draft.
    The next user message is a new turn, so nothing here calls interrupt.
    """
    human = [m for m in state.get("messages") or [] if getattr(m, "type", None) == "human"]
    text = _message_text(human[-1]).strip() if human else ""
    phase = state.get("phase")
    saved = [dict(item) for item in state.get("targets") or []] if phase in {"collecting", "awaiting_confirm"} else []

    if phase == "awaiting_confirm" and _is_confirm(text) and saved and not any(_missing(target) for target in saved):
        return {
            "phase": "running",
            "input_error": None,
            "messages": [AIMessage(content=_starting_text(saved))],
        }

    targets = _combine(saved, text)
    _fill_models(targets)
    note = ""
    if len(targets) > MAX_TARGETS:
        note = f"\n\nOnly the first {MAX_TARGETS} targets will run."
        targets = targets[:MAX_TARGETS]
    gaps = _gap_lines(targets)
    base = {"targets": targets, "target_index": 0, "results": [], "run": {}}
    if gaps:
        return {
            **base,
            "phase": "collecting",
            "input_error": "; ".join(gaps),
            "messages": [AIMessage(content=_missing_text(targets, gaps, note))],
        }
    return {
        **base,
        "phase": "awaiting_confirm",
        "input_error": None,
        "messages": [AIMessage(content=_ready_text(targets, note))],
    }


def route_after_input(state: ChatState) -> str:
    return "start" if state.get("phase") == "running" else "end"


# ---------------------------------------------------------------------------
# Per-target lifecycle
# ---------------------------------------------------------------------------

def _current_target(state: ChatState) -> dict[str, Any]:
    return state["targets"][state.get("target_index") or 0]


def _label(state: ChatState) -> str:
    targets = state.get("targets") or []
    if len(targets) <= 1:
        return ""
    index = state.get("target_index") or 0
    return f"**[{index + 1}/{len(targets)} {targets[index]['package_name']}]** "


def start_target(state: ChatState) -> dict:
    """Give the next target a fresh pipeline state, exactly like batch_runner does."""
    target = _current_target(state)
    run = _fresh_state(
        target["package_name"],
        target["package_version"],
        model_provider=os.getenv("MODEL_PROVIDER", "openrouter"),
        model_name=target["model_name"],
        max_retries=int(os.getenv("MAX_RETRIES", "1")),
        patch_scope="single",
    )
    run["user_prompt"] = target.get("user_prompt") or ""
    run["suspected_issue"] = target.get("suspected_issue") or ""
    run["maintainer_commit_url"] = target.get("maintainer_commit_url") or ""
    run["intake_confirmed"] = True
    return {"run": run}


def _select_vulnerability(target: dict[str, Any], result: dict) -> dict:
    """Pin the requested advisory, like test_local_pipeline --vulnerability-id."""
    requested = (target.get("vulnerability_id") or "").casefold()
    found = result.get("current_vulnerabilities") or []
    if not requested or not found:
        return result
    match = next(
        (v for v in found if requested in {str(i).casefold() for i in [v.get("id"), *(v.get("aliases") or [])] if i}),
        None,
    )
    return {**result, "current_vulnerabilities": [match] if match else []}


def route_after_detection(state: ChatState) -> str:
    run = state.get("run") or {}
    return "continue" if run.get("source_dir") and run.get("current_vulnerabilities") else "stop"


def _result_row(state: ChatState) -> dict[str, Any]:
    target, run = _current_target(state), state.get("run") or {}
    selected = (run.get("current_vulnerabilities") or [{}])[0]
    return {
        "package": f"{target['package_name']}@{target['package_version']}",
        "advisory": selected.get("id") or target.get("vulnerability_id") or "none detected",
        "model": target["model_name"],
        "classification": run.get("classification") or "not run",
        "category": (run.get("final_evaluation") or {}).get("category"),
        "oracle": (run.get("generated_patch_oracle_validation") or {}).get("status"),
        "maintainer": (run.get("maintainer_eval") or {}).get("verdict"),
        "cost": float(run.get("run_cost") or 0),
        "reason": run.get("classification_reason") or _stop_reason(target, run),
    }


def _stop_reason(target: dict[str, Any], run: dict[str, Any]) -> str:
    if not run.get("source_dir"):
        return "Package could not be downloaded."
    if not run.get("current_vulnerabilities"):
        requested = target.get("vulnerability_id")
        return f"Advisory {requested} was not detected." if requested else "No vulnerability detected."
    return "Run stopped early."


def finish_target(state: ChatState) -> dict:
    row = _result_row(state)
    icon = {"pass": "✅", "pass_unverified": "🟡", "inconclusive": "🟡"}.get(row["classification"], "❌")
    extra = f" ({row['category']})" if row["category"] else ""
    text = f"{_label(state)}🏁 **{row['package']}: {icon} {row['classification'].upper()}**{extra}, ${row['cost']:.2f}. {row['reason']}"
    return {
        "results": [*(state.get("results") or []), row],
        "target_index": (state.get("target_index") or 0) + 1,
        "messages": [AIMessage(content=text)],
    }


def route_after_target(state: ChatState) -> str:
    return "next" if (state.get("target_index") or 0) < len(state.get("targets") or []) else "done"


def batch_summary(state: ChatState) -> dict:
    results = state.get("results") or []
    if len(results) < 2:
        return {"phase": "done"}
    rows = "\n".join(
        f"| {r['package']} | {r['advisory']} | `{r['model']}` | {r['classification']} | "
        f"{r['category'] or '–'} | {r['oracle'] or '–'} | {r['maintainer'] or '–'} | ${r['cost']:.2f} |"
        for r in results
    )
    table = (
        "| Package | Advisory | Model | Result | Category | Security test | Vs maintainer | Cost |\n"
        "|---|---|---|---|---|---|---|---|\n" + rows
    )
    total = sum(r["cost"] for r in results)
    return {
        "phase": "done",
        "messages": [AIMessage(content=f"📊 **Summary** (total ${total:.2f})\n\n{table}")],
    }


# ---------------------------------------------------------------------------
# Step summaries (written after each step; never shown to the model)
# ---------------------------------------------------------------------------

STEP_TITLES = {
    "intake_node": "📝 Confirm prompt",
    "package_input_node": "📦 Package input",
    "vulnerability_detection_node": "🔍 Vulnerability detection",
    "og_patch_resolution_node": "📚 Maintainer fix lookup",
    "locator_node": "🧭 Locator",
    "vulnerability_localization_node": "🎯 Vulnerability localization",
    "oracle_generation_node": "🧪 Security test generation",
    "oracle_validation_node": "🧪 Security test check",
    "patch_generation_node": "🤖 Patch generation",
    "apply_patch_node": "🩹 Apply patch",
    "generated_patch_oracle_validation_node": "🛡️ Security test on patch",
    "record_locked_oracle_failure_node": "↩️ Security test failed",
    "skip_package_tests_node": "⏭️ Package tests",
    "package_validation_node": "🐳 Package tests",
    "vulnerability_rescan_node": "🔁 Rescan",
    "adversarial_evaluation_node": "🧑‍⚖️ Independent review",
    "patch_validation_node": "🏁 Validation",
    "patch_scoring_node": "📐 Scoring",
    "final_evaluation_node": "🧾 Final evaluation",
    "maintainer_eval_node": "📝 Maintainer comparison",
    "increment_retry": "↩️ Retry",
}


def _title(step: str) -> str:
    return STEP_TITLES.get(step) or "⚙️ " + step.removesuffix("_node").replace("_", " ").capitalize()


def _summary(step: str, run: dict) -> str | None:
    """Short summary of a finished step, or None for intermediate tool-loop steps."""
    if step in {"repo_graph_node", "intake_node"}:
        return None  # graph lookups, or a confirmation already shown in the thread
    if step == "locator_node":
        if run.get("graph_request") or run.get("locate_status") == "running":
            return None
        spots = [
            f"`{loc.get('path')}{':' + loc['function'] if loc.get('function') else ''}`"
            for loc in (run.get("debug_locations") or [])[:5]
        ]
        return f"Locator {run.get('locate_status')}: {', '.join(spots) or 'no locations'}."
    if step == "patch_generation_node" and run.get("graph_request"):
        return None
    if step == "package_input_node":
        if run.get("source_dir"):
            return f"Downloaded and unpacked {run['package_name']}@{run['package_version']}."
        return f"Could not download the package: {'; '.join(run.get('errors') or []) or 'unknown error'}"
    if step == "vulnerability_detection_node":
        selected = run.get("current_vulnerabilities") or []
        if not selected:
            return "No matching vulnerability detected; skipping this target."
        v = selected[0]
        return (
            f"Target: **{v.get('id')}** ({v.get('severity')}): {v.get('description')}. "
            f"Fixed in {v.get('fixed_version') or 'no released version'}."
        )
    if step == "og_patch_resolution_node":
        key = run.get("answer_key") or {}
        commits = ", ".join(c.get("sha", "")[:7] for c in key.get("commit_refs") or []) or "none linked"
        return f"Maintainer fix: {key.get('status')} (commits: {commits}). Kept hidden from the model."
    if step == "vulnerability_localization_node":
        files = run.get("localized_files") or []
        listed = ", ".join(f"`{name}`" for name in files[:6]) + (f" and {len(files) - 6} more" if len(files) > 6 else "")
        return f"Localization {run.get('localization_status')}: {listed or 'no files'}."
    if step == "oracle_generation_node":
        candidate = run.get("oracle_candidate") or {}
        return f"Security test {candidate.get('status') or 'not generated'} (attempt {run.get('oracle_attempt_count') or 1})."
    if step == "oracle_validation_node":
        check = run.get("oracle_validation") or {}
        return f"Security test on vulnerable vs maintainer-fixed package: **{check.get('status')}**. {(check.get('reason') or '')[:300]}"
    if step == "patch_generation_node":
        if run.get("generation_status") == "failed":
            return f"No patch produced: {run.get('generation_error')}"
        patch = run.get("current_patch") or {}
        diff = (patch.get("diff") or "")[:MAX_DIFF_CHARS]
        files = ", ".join(patch.get("target_files") or []) or "unknown files"
        return f"`{patch.get('model_used')}` patched {files}:\n\n```diff\n{diff}\n```"
    if step == "apply_patch_node":
        return "Patch applied." if run.get("patch_applied") else "Patch did not apply to the package."
    if step == "generated_patch_oracle_validation_node":
        check = run.get("generated_patch_oracle_validation") or {}
        return f"Security test on the patched package: **{check.get('status')}**. {(check.get('reason') or '')[:300]}"
    if step == "record_locked_oracle_failure_node":
        return "The patch did not pass the security test; the writer gets that output and tries again."
    if step == "skip_package_tests_node":
        return "Skipped: the patch failed the security test and no attempts are left."
    if step == "package_validation_node":
        v = run.get("validation") or {}
        mark = {"PASS": "✅", "FAIL": "❌", "SKIPPED": "–"}
        stages = [
            ("Docker", v.get("docker_status")),
            ("install", v.get("installation_status")),
            ("build", v.get("build_status")),
            ("tests", v.get("test_status")),
            ("consumer smoke", v.get("consumer_smoke_status")),
        ]
        checks = ", ".join(f"{name} {mark.get(status, '?')}" for name, status in stages if status)
        failed_at = f" Failed at: {v['failure_stage']}." if v.get("failure_stage") else ""
        return f"Sandbox: {checks or 'no results'}.{failed_at} Vs unpatched package: **{run.get('regression_status')}**."
    if step == "vulnerability_rescan_node":
        remaining = len(run.get("remaining_vulnerabilities") or [])
        return f"Version-based rescan still reports {remaining} finding(s); expected, since the version number is unchanged."
    if step == "adversarial_evaluation_node":
        e = run.get("adversarial_evaluation") or {}
        return f"`{e.get('evaluator_model')}` review: genuine fix = **{e.get('genuine_fix')}**. {(e.get('reasoning') or '')[:400]}"
    if step == "patch_validation_node":
        category = (run.get("final_evaluation") or {}).get("category")
        saved = f"saved as {run['mongo_id']}" if run.get("mongo_id") else "not saved (MongoDB unavailable)"
        extra = f" ({category})" if category else ""
        return f"**{str(run.get('classification')).upper()}**{extra}: {run.get('classification_reason')} ({saved})"
    if step == "patch_scoring_node":
        s = run.get("patch_score") or {}
        return f"Vs maintainer fix: location {s.get('location')}, strategy {s.get('strategy')}, completeness {s.get('completeness')}."
    if step == "final_evaluation_node":
        f = run.get("final_evaluation") or {}
        return (
            f"**{f.get('category')}**: {f.get('reason')} "
            f"(security test {f.get('oracle_status')}, review {f.get('adversarial_verdict')}, "
            f"package tests {f.get('compatibility_status')})"
        )
    if step == "maintainer_eval_node":
        m = run.get("maintainer_eval") or {}
        return f"Maintainer-fix comparison: **{m.get('verdict')}**. {(m.get('summary') or '')[:500]}"
    if step == "increment_retry":
        return f"Retrying (attempt {(run.get('retry_count') or 0) + 1})."
    return "Done."


# ---------------------------------------------------------------------------
# Building the chat graph around graph.py's pipeline
# ---------------------------------------------------------------------------

def _pipeline_step(step: str, node: Callable[[dict], dict]) -> Callable[[ChatState], dict]:
    """Run a pipeline node on the current target's state and post its summary."""

    def run(state: ChatState) -> dict:
        current = dict(state.get("run") or {})
        started = time.monotonic()
        update = node(dict(current)) or {}
        if step == "vulnerability_detection_node":
            update = _select_vulnerability(_current_target(state), update)
        merged = {**current, **update}
        out: dict[str, Any] = {"run": merged}
        summary = _summary(step, merged)
        if summary is not None:
            seconds = time.monotonic() - started
            out["messages"] = [AIMessage(content=f"{_label(state)}{_title(step)} ({seconds:.0f}s)\n\n{summary}")]
        return out

    return run


def _route_on_run(path: Callable[[dict], Any]) -> Callable[[ChatState], Any]:
    """Apply a pipeline routing rule to the current target's state; END means the target is done."""

    def route(state: ChatState) -> Any:
        choice = path(state.get("run") or {})
        return "finish_target" if choice == END else choice

    return route


def _callable(runnable: Any) -> Callable[[dict], Any]:
    return getattr(runnable, "func", None) or runnable.invoke


def build_chat_graph(pipeline: Any = pipeline_graph, checkpointer: Any = None):
    """Wrap a compiled pipeline graph (graph.py by default) with the chat front end."""
    source = pipeline.builder
    builder = StateGraph(ChatState)
    builder.add_node("chat_input", chat_input)
    builder.add_node("start_target", start_target)
    builder.add_node("finish_target", finish_target)
    builder.add_node("batch_summary", batch_summary)
    for name, spec in source.nodes.items():
        builder.add_node(name, _pipeline_step(name, _callable(spec.runnable)))

    builder.add_edge(START, "chat_input")
    builder.add_conditional_edges("chat_input", route_after_input, {"start": "start_target", "end": END})
    for start, end in source.edges:
        if start == START:
            builder.add_edge("start_target", end)
        elif start == "vulnerability_detection_node":
            # Stop this target early if the package or the requested advisory is missing.
            builder.add_conditional_edges(start, route_after_detection, {"continue": end, "stop": "finish_target"})
        else:
            builder.add_edge(start, "finish_target" if end == END else end)
    for start, branches in source.branches.items():
        for branch in branches.values():
            ends = {key: ("finish_target" if target == END else target) for key, target in (branch.ends or {}).items()}
            builder.add_conditional_edges(start, _route_on_run(_callable(branch.path)), ends or None)
    builder.add_conditional_edges("finish_target", route_after_target, {"next": "start_target", "done": "batch_summary"})
    builder.add_edge("batch_summary", END)
    return builder.compile(checkpointer=checkpointer)


graph = build_chat_graph()
