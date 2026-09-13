from __future__ import annotations

import difflib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any
import uuid

from dotenv import load_dotenv
from openai import OpenAI

try:
    from google import genai
except ImportError:
    genai = None

from state import GraphState, PatchAttempt, Vulnerability

load_dotenv()

logger = logging.getLogger(__name__)


DEFAULT_MODELS = {
    "mock": "mock-diff-v1",
    "openai": "gpt-4.1-mini",
    "anthropic": "claude-sonnet-4-0",
    "gemini": "gemini-3.6-flash",
    "openrouter": "nvidia/nemotron-3-super-120b-a12b:free",
}

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "baseline.txt"
MAX_CONTEXT_FILES = 16
MAX_CONTEXT_CHARS_PER_FILE = 8_000
MAX_SOURCE_CONTEXT_CHARS = 28_000
MAX_DEPENDENCY_CONTEXT_FILES = 8
MAX_OPENROUTER_CONTEXT_CHARS = 36_000
OPENROUTER_MAX_TOKENS = 16_000
SOURCE_SUFFIXES = (".js", ".cjs", ".mjs", ".ts")
LOCAL_IMPORT_PATTERN = re.compile(
    r"(?:require\(\s*|from\s+|import\s*)[\"'](\.[^\"']+)[\"']"
)


def _with_error(state: GraphState, message: str, **extra: Any) -> dict:
    errors = list(state.get("errors", []))
    errors.append(message)
    payload = {"errors": errors}
    payload.update(extra)
    return payload


def _generation_failure(
    state: GraphState,
    message: str,
    *,
    provider: str | None = None,
    model_name: str | None = None,
) -> dict:
    """Return an explicit terminal generation result for graph routing and storage."""
    extra: dict[str, Any] = {
        "generation_status": "failed",
        "generation_error": message,
        # Clear a stale patch if generation fails to produce a replacement.
        "current_patch": None,
    }
    if provider:
        extra["generation_provider"] = provider
    if model_name:
        extra["generation_model_used"] = model_name
    return _with_error(state, message, **extra)


def _pick_target_vulnerability(vulnerabilities: list[Vulnerability]) -> Vulnerability | None:
    if not vulnerabilities:
        return None
    return vulnerabilities[0]


def _select_vulnerabilities(state: GraphState) -> list[Vulnerability]:
    vulnerabilities = state.get("current_vulnerabilities") or state.get("vulnerabilities", [])
    if not vulnerabilities:
        return []

    patch_scope = state.get("patch_scope", "single")
    if patch_scope == "all":
        return vulnerabilities

    target = _pick_target_vulnerability(vulnerabilities)
    return [target] if target else []


def _focus_terms(vulnerabilities: list[Vulnerability]) -> set[str]:
    """Extract identifier-like terms from scanner findings for source excerpting."""
    terms: set[str] = set()
    for vulnerability in vulnerabilities:
        text = " ".join(
            str(vulnerability.get(key, ""))
            for key in ("id", "description", "title", "details")
        )
        for term in re.findall(r"[A-Za-z_$][A-Za-z0-9_$-]{2,}", text):
            if term.lower() not in {"cve", "ghsa", "vulnerability", "package", "version"}:
                terms.add(term.lower())
    return terms


def _source_excerpt(contents: str, focus_terms: set[str]) -> str:
    """Keep a bounded excerpt with the beginning, relevant matches, and the end."""
    if len(contents) <= MAX_CONTEXT_CHARS_PER_FILE:
        return contents

    ranges: list[tuple[int, int]] = [(0, 2_000), (len(contents) - 2_000, len(contents))]
    for term in sorted(focus_terms, key=len, reverse=True)[:12]:
        match = re.search(re.escape(term), contents, re.IGNORECASE)
        if match:
            ranges.append((max(0, match.start() - 1_500), min(len(contents), match.end() + 2_500)))

    selected: list[tuple[int, int]] = []
    used = 0
    for start, end in sorted(ranges):
        start = contents.rfind("\n", 0, start) + 1
        end_newline = contents.find("\n", end)
        end = len(contents) if end_newline == -1 else end_newline + 1
        if selected and start <= selected[-1][1]:
            selected[-1] = (selected[-1][0], max(selected[-1][1], end))
            continue
        if used + (end - start) > MAX_CONTEXT_CHARS_PER_FILE:
            continue
        selected.append((start, end))
        used += end - start

    excerpts: list[str] = []
    previous_end = 0
    for start, end in selected:
        if start > previous_end:
            excerpts.append("\n// ... omitted unrelated source ...\n")
        excerpts.append(contents[start:end])
        previous_end = end
    return "".join(excerpts)


def _read_context_files(
    source_dir: Path,
    manifest_path: Path,
    focus_terms: set[str] | None = None,
) -> list[dict[str, str]]:
    context_files: list[Path] = []
    queued_modules: list[Path] = []

    def add_context_file(path: Path, *, queue_for_imports: bool = False) -> None:
        if len(context_files) >= MAX_CONTEXT_FILES or path in context_files:
            return
        context_files.append(path)
        if queue_for_imports:
            queued_modules.append(path)

    def resolve_local_module(importer: Path, specifier: str) -> Path | None:
        base_path = importer.parent / specifier
        candidates = [base_path]
        if not base_path.suffix:
            candidates.extend(base_path.with_suffix(suffix) for suffix in SOURCE_SUFFIXES)
            candidates.extend(base_path / f"index{suffix}" for suffix in SOURCE_SUFFIXES)
        for candidate in candidates:
            try:
                candidate.resolve().relative_to(source_dir.resolve())
            except ValueError:
                continue
            if candidate.is_file():
                return candidate
        return None

    add_context_file(manifest_path)

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        manifest = {}

    for key in ("main", "module", "browser"):
        candidate = manifest.get(key)
        if isinstance(candidate, str):
            candidate_path = source_dir / candidate
            if candidate_path.is_file():
                add_context_file(candidate_path, queue_for_imports=True)

    fallback_files = [
        source_dir / "index.js",
        source_dir / "src" / "index.js",
        source_dir / "lib" / "index.js",
    ]
    for candidate_path in fallback_files:
        if candidate_path.is_file():
            add_context_file(candidate_path, queue_for_imports=True)

    # Follow the package entrypoint's local imports first. This produces a
    # focused code slice instead of an alphabetical sample of unrelated files.
    while queued_modules and len(context_files) < MAX_DEPENDENCY_CONTEXT_FILES:
        importer = queued_modules.pop(0)
        try:
            contents = importer.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for specifier in LOCAL_IMPORT_PATTERN.findall(contents):
            dependency = resolve_local_module(importer, specifier)
            if dependency:
                add_context_file(dependency, queue_for_imports=True)

    # Reserve remaining context for published tests, then fill any unused
    # capacity with implementation files as a bounded fallback.
    test_candidates = [
        path
        for path in sorted(source_dir.rglob("*"))
        if path.is_file()
        and path.suffix.lower() in {*SOURCE_SUFFIXES, ".json"}
        and any(part in {"test", "tests", "__tests__"} for part in path.relative_to(source_dir).parts)
    ]
    for candidate_path in test_candidates:
        add_context_file(candidate_path, queue_for_imports=True)

    for candidate_path in sorted(source_dir.rglob("*")):
        if not candidate_path.is_file():
            continue
        if candidate_path.suffix.lower() not in {".js", ".cjs", ".mjs", ".ts", ".json"}:
            continue
        add_context_file(candidate_path)

    snippets = []
    context_chars = 0
    focus_terms = focus_terms or set()
    for path in context_files:
        try:
            contents = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        excerpt = _source_excerpt(contents, focus_terms)
        if context_chars + len(excerpt) > MAX_SOURCE_CONTEXT_CHARS:
            continue
        snippets.append(
            {
                "path": str(path.relative_to(source_dir)).replace("\\", "/"),
                "content": excerpt,
            }
        )
        context_chars += len(excerpt)
    return snippets


def _build_messages(
    state: GraphState,
    vulnerabilities: list[Vulnerability],
    context_files: list[dict[str, str]],
) -> list[dict[str, str]]:
    system_prompt = (
        "You generate minimal security patches for npm packages. "
        "Return valid JSON only. The diff must be a unified diff relative to the package root. "
        "Only change files that are necessary for the fix."
    )
    user_payload = {
        "package_name": state.get("package_name"),
        "package_version": state.get("package_version"),
        "patch_scope": state.get("patch_scope", "single"),
        "vulnerabilities": vulnerabilities,
        "context_files": context_files,
        "output_schema": {
            "diff": "string, unified diff relative to package root",
            "target_files": "optional list of changed file paths relative to package root",
        },
    }
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_payload)},
    ]


def _build_openrouter_prompt(
    state: GraphState,
    vulnerabilities: list[Vulnerability],
    context_files: list[dict[str, str]],
) -> str:
    if not OPENROUTER_PROMPT_PATH.is_file():
        return "\n\n".join(message["content"] for message in _build_messages(state, vulnerabilities, context_files))

    vulnerability = vulnerabilities[0]
    relevant_source_code = "\n\n".join(
        f"--- {file['path']} ---\n{file['content']}" for file in context_files
    )
    relevant_source_code = relevant_source_code[:MAX_OPENROUTER_CONTEXT_CHARS]
    template = OPENROUTER_PROMPT_PATH.read_text(encoding="utf-8")
    prompt = template.format(
        vulnerability_id=vulnerability.get("id", "unknown"),
        vulnerability_class=vulnerability.get("severity", "unknown"),
        vulnerability_description=vulnerability.get("description", ""),
        scanner_finding=json.dumps(vulnerability),
        relevant_source_code=relevant_source_code,
        relevant_tests="Tests are included in the repository context. Do not modify them.",
    )
    logger.info("OpenRouter rendered prompt:\n%s", prompt)
    return prompt


def _parse_patch_response(content: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        diff = payload.get("diff")
        if isinstance(diff, str):
            extracted_diff = _extract_unified_diff(diff)
            if extracted_diff:
                payload["diff"] = extracted_diff
        return payload if _is_complete_unified_diff(payload.get("diff")) else None

    diff = _extract_unified_diff(content)
    if not diff:
        return None
    return {"diff": diff + "\n"}


def _is_complete_unified_diff(diff: Any) -> bool:
    if not isinstance(diff, str) or not diff.strip():
        return False
    lines = diff.splitlines()
    saw_file = False
    in_hunk = False
    expecting_new_path = False
    hunk_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")

    for line in lines:
        if line.startswith("diff --git "):
            if expecting_new_path:
                return False
            in_hunk = False
            continue
        if line.startswith("index "):
            continue
        if line.startswith("--- a/"):
            saw_file = True
            in_hunk = False
            expecting_new_path = True
            continue
        if line.startswith("+++ b/"):
            if not saw_file or not expecting_new_path:
                return False
            expecting_new_path = False
            continue
        if hunk_pattern.match(line):
            if not saw_file or expecting_new_path:
                return False
            in_hunk = True
            continue
        if in_hunk and (line.startswith((" ", "+", "-", "\\ No newline at end of file")) or not line):
            continue
        return False
    return saw_file and in_hunk and not expecting_new_path


def _extract_unified_diff(content: str) -> str | None:
    fenced_blocks = re.findall(r"```(?:diff|patch|text)?\s*(.*?)```", content, re.DOTALL | re.IGNORECASE)
    candidates = fenced_blocks or [content]
    for candidate in candidates:
        match = re.search(r"(?:^|\n)(diff --git\s+|---\s+a/).*", candidate)
        if match:
            return candidate[match.start(1):].strip()
    return None


def _build_run_attempt_id(state: GraphState) -> str:
    """Build a unique, readable ID that persists across retries in one run."""
    package_name = state.get("package_name") or "package"
    return f"{package_name}-{uuid.uuid4()}"


def _build_mock_payload(
    source_dir: Path,
    selected_vulnerabilities: list[Vulnerability],
    context_files: list[dict[str, str]],
) -> dict[str, Any]:
    target_path = None
    for snippet in context_files:
        candidate = source_dir / snippet["path"]
        if candidate.suffix.lower() in {".js", ".cjs", ".mjs", ".ts"} and candidate.exists():
            target_path = candidate
            break

    if target_path is None:
        target_path = source_dir / "package.json"

    try:
        original = target_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        original = target_path.read_text(encoding="utf-8", errors="ignore")

    target_label = (
        selected_vulnerabilities[0].get("id", "unknown")
        if len(selected_vulnerabilities) == 1
        else f"{len(selected_vulnerabilities)} vulnerabilities"
    )
    comment = f"// MOCK PATCH for {target_label}\n"
    patched = original if original.startswith(comment) else comment + original

    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{target_path.relative_to(source_dir).as_posix()}",
            tofile=f"b/{target_path.relative_to(source_dir).as_posix()}",
        )
    )

    return {
        "diff": diff,
        "target_files": [target_path.relative_to(source_dir).as_posix()],
    }


def _generate_with_openai(
    state: GraphState,
    selected_vulnerabilities: list[Vulnerability],
    context_files: list[dict[str, str]],
) -> dict[str, Any] | str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "patch_generation: OPENAI_API_KEY is not set"

    model_name = state.get("model_name", "gpt-4.1-mini")
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        messages=_build_messages(state, selected_vulnerabilities, context_files),
    )
    content = response.choices[0].message.content or ""
    payload = _parse_patch_response(content)
    return payload if payload is not None else "patch_generation: model returned an invalid patch response"


def _generate_with_openrouter(
    state: GraphState,
    selected_vulnerabilities: list[Vulnerability],
    context_files: list[dict[str, str]],
) -> dict[str, Any] | str:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return "patch_generation: OPENROUTER_API_KEY is not set"

    model_name = state.get("model_name", DEFAULT_MODELS["openrouter"])
    client = OpenAI(
        api_key=api_key,
        base_url=os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL),
        timeout=180.0,
    )
    system_message = (
        "You are a patch emitter, not an analyst. Return one JSON object and nothing else. "
        'Its only required field is "diff", whose value is a complete applyable unified diff. '
        "Do not include an explanation, summary, Markdown fence, rationale, or a partial diff."
    )
    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": _build_openrouter_prompt(state, selected_vulnerabilities, context_files)},
    ]
    try:
        response = client.chat.completions.create(
            model=model_name,
            temperature=0,
            max_tokens=OPENROUTER_MAX_TOKENS,
            response_format={"type": "json_object"},
            extra_body={"reasoning": {"enabled": False, "exclude": True}},
            messages=messages,
        )
    except Exception as exc:
        return f"patch_generation: OpenRouter request failed: {type(exc).__name__}: {exc!r}"

    choices = getattr(response, "choices", None) or []
    if not choices:
        response_status = getattr(response, "status_code", "unknown")
        return f"patch_generation: model returned no choices (status_code={response_status})"

    choice = choices[0]
    message = getattr(choice, "message", None)
    if message is None:
        return "patch_generation: model returned no message"
    content = (message.content or "").strip()
    payload = _parse_patch_response(content)
    if payload is not None:
        return payload

    finish_reason = getattr(choice, "finish_reason", "unknown")
    preview = content[:300].replace("\n", " ") if content else "<empty response>"
    return (
        "patch_generation: model returned an invalid or incomplete patch response "
        f"(finish_reason={finish_reason}, preview={preview!r})"
    )


def _generate_with_anthropic(
    state: GraphState,
    selected_vulnerabilities: list[Vulnerability],
    context_files: list[dict[str, str]],
) -> dict[str, Any] | str:
    try:
        from anthropic import Anthropic
    except ImportError:
        return "patch_generation: anthropic package is not installed"

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return "patch_generation: ANTHROPIC_API_KEY is not set"

    model_name = state.get("model_name", "claude-sonnet-4-0")
    client = Anthropic(api_key=api_key)
    messages = _build_messages(state, selected_vulnerabilities, context_files)
    response = client.messages.create(
        model=model_name,
        max_tokens=4000,
        system=messages[0]["content"],
        messages=[{"role": "user", "content": messages[1]["content"]}],
    )
    text_blocks = [block.text for block in response.content if getattr(block, "type", "") == "text"]
    content = "".join(text_blocks).strip()
    payload = _parse_patch_response(content)
    return payload if payload is not None else "patch_generation: model returned an invalid patch response"


def _generate_with_gemini(
    state: GraphState,
    selected_vulnerabilities: list[Vulnerability],
    context_files: list[dict[str, str]],
) -> dict[str, Any] | str:
    if genai is None:
        return "patch_generation: google-genai package is not installed"

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "patch_generation: GEMINI_API_KEY is not set"

    model_name = state.get("model_name", DEFAULT_MODELS["gemini"])
    messages = _build_messages(state, selected_vulnerabilities, context_files)
    client = genai.Client(api_key=api_key)
    try:
        response = client.models.generate_content(
            model=model_name,
            contents=messages[1]["content"],
            config={
                "system_instruction": messages[0]["content"],
                "response_mime_type": "application/json",
            },
        )
    except Exception as exc:
        return f"patch_generation: Gemini request failed: {exc}"

    content = (getattr(response, "text", None) or "").strip()
    if not content:
        return "patch_generation: Gemini returned an empty response"
    payload = _parse_patch_response(content)
    return payload if payload is not None else "patch_generation: model returned an invalid patch response"


def patch_generation(state: GraphState) -> dict:
    source_dir = state.get("source_dir")
    if not source_dir:
        return _generation_failure(state, "patch_generation: missing source_dir")

    selected_vulnerabilities = _select_vulnerabilities(state)
    if not selected_vulnerabilities:
        return _generation_failure(state, "patch_generation: no vulnerabilities available for patching")

    source_path = Path(source_dir)
    manifest_path_value = state.get("package_manifest_path")
    manifest_path = Path(manifest_path_value) if manifest_path_value else source_path / "package.json"
    if not manifest_path.exists():
        return _generation_failure(state, f"patch_generation: package manifest not found: {manifest_path}")

    provider = state.get("model_provider", "mock")
    default_model = DEFAULT_MODELS.get(provider)
    if default_model is None:
        return _generation_failure(state, f"patch_generation: unsupported model_provider: {provider}", provider=provider)
    model_name = state.get("model_name", default_model)
    context_files = _read_context_files(
        source_path,
        manifest_path,
        _focus_terms(selected_vulnerabilities),
    )

    if provider == "mock":
        payload = _build_mock_payload(source_path, selected_vulnerabilities, context_files)
    elif provider == "openai":
        payload = _generate_with_openai(state, selected_vulnerabilities, context_files)
    elif provider == "anthropic":
        payload = _generate_with_anthropic(state, selected_vulnerabilities, context_files)
    elif provider == "gemini":
        payload = _generate_with_gemini(state, selected_vulnerabilities, context_files)
    elif provider == "openrouter":
        payload = _generate_with_openrouter(state, selected_vulnerabilities, context_files)
    else:
        return _generation_failure(state, f"patch_generation: unsupported model_provider: {provider}", provider=provider, model_name=model_name)

    if isinstance(payload, str):
        return _generation_failure(state, payload, provider=provider, model_name=model_name)

    diff = payload.get("diff")
    if not isinstance(diff, str) or not diff.strip():
        return _generation_failure(
            state,
            "patch_generation: model response did not contain a diff",
            provider=provider,
            model_name=model_name,
        )

    patch_attempts = list(state.get("patch_attempts", []))
    attempt_number = len(patch_attempts) + 1

    # The run_attempt_id is stable for the entire run (same vuln / scope).
    # On the first attempt we derive and store it; on retries we reuse it.
    run_attempt_id = state.get("run_attempt_id") or _build_run_attempt_id(state)

    patch_attempt = PatchAttempt(
        attempt_number=attempt_number,
        attempt_id=run_attempt_id,
        diff=diff,
        model_used=model_name,
    )
    if len(selected_vulnerabilities) == 1:
        patch_attempt["vulnerability_id"] = selected_vulnerabilities[0].get("id", "unknown")
    target_files = payload.get("target_files")
    if isinstance(target_files, list) and all(isinstance(path, str) for path in target_files):
        patch_attempt["target_files"] = target_files
    patch_attempts.append(patch_attempt)

    return {
        "patch_attempts": patch_attempts,
        "current_patch": patch_attempt,
        "run_attempt_id": run_attempt_id,
        "generation_status": "generated",
        "generation_error": None,
        "generation_provider": provider,
        "generation_model_used": model_name,
    }
