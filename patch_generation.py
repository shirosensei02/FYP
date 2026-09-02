from __future__ import annotations

import difflib
import json
import os
from pathlib import Path
from typing import Any
import uuid

from dotenv import load_dotenv
from openai import OpenAI

from state import GraphState, PatchAttempt, Vulnerability

load_dotenv()


def _with_error(state: GraphState, message: str, **extra: Any) -> dict:
    errors = list(state.get("errors", []))
    errors.append(message)
    payload = {"errors": errors}
    payload.update(extra)
    return payload


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


def _read_context_files(source_dir: Path, manifest_path: Path) -> list[dict[str, str]]:
    context_files: list[Path] = [manifest_path]

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        manifest = {}

    for key in ("main", "module", "browser"):
        candidate = manifest.get(key)
        if isinstance(candidate, str):
            candidate_path = source_dir / candidate
            if candidate_path.is_file():
                context_files.append(candidate_path)

    fallback_files = [
        source_dir / "index.js",
        source_dir / "src" / "index.js",
        source_dir / "lib" / "index.js",
    ]
    for candidate_path in fallback_files:
        if candidate_path.is_file():
            context_files.append(candidate_path)

    for candidate_path in source_dir.rglob("*"):
        if not candidate_path.is_file():
            continue
        if candidate_path.suffix.lower() not in {".js", ".cjs", ".mjs", ".ts", ".json"}:
            continue
        context_files.append(candidate_path)
        if len(context_files) >= 25:
            break

    unique_files: list[Path] = []
    seen = set()
    for path in context_files:
        if path in seen:
            continue
        seen.add(path)
        unique_files.append(path)

    snippets = []
    for path in unique_files[:25]:
        try:
            contents = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        snippets.append(
            {
                "path": str(path.relative_to(source_dir)).replace("\\", "/"),
                "content": contents[:12000],
            }
        )
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
        },
    }
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_payload)},
    ]


def _build_run_attempt_id(state: GraphState) -> dict:
    """Build a unique ID based on the package name and a random UUID"""
    unique_id = str(uuid.uuid4())
    package_name = state.get("package_name")

    return package_name + unique_id


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
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        return f"patch_generation: model returned invalid JSON: {exc}"


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
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        return f"patch_generation: model returned invalid JSON: {exc}"


def patch_generation(state: GraphState) -> dict:
    source_dir = state.get("source_dir")
    if not source_dir:
        return _with_error(state, "patch_generation: missing source_dir")

    selected_vulnerabilities = _select_vulnerabilities(state)
    if not selected_vulnerabilities:
        return _with_error(state, "patch_generation: no vulnerabilities available for patching")

    source_path = Path(source_dir)
    manifest_path_value = state.get("package_manifest_path")
    manifest_path = Path(manifest_path_value) if manifest_path_value else source_path / "package.json"
    if not manifest_path.exists():
        return _with_error(state, f"patch_generation: package manifest not found: {manifest_path}")

    provider = state.get("model_provider", "mock")
    default_model = "mock-diff-v1" if provider == "mock" else "gpt-4.1-mini"
    model_name = state.get("model_name", default_model)
    context_files = _read_context_files(source_path, manifest_path)

    if provider == "mock":
        payload = _build_mock_payload(source_path, selected_vulnerabilities, context_files)
    elif provider == "openai":
        payload = _generate_with_openai(state, selected_vulnerabilities, context_files)
    elif provider == "anthropic":
        payload = _generate_with_anthropic(state, selected_vulnerabilities, context_files)
    else:
        return _with_error(state, f"patch_generation: unsupported model_provider: {provider}")

    if isinstance(payload, str):
        return _with_error(state, payload)

    diff = payload.get("diff")
    if not isinstance(diff, str) or not diff.strip():
        return _with_error(state, "patch_generation: model response did not contain a diff")

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
    patch_attempts.append(patch_attempt)

    return {
        "patch_attempts": patch_attempts,
        "current_patch": patch_attempt,
        "run_attempt_id": run_attempt_id,
    }
