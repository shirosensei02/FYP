from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

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

    unique_files: list[Path] = []
    seen = set()
    for path in context_files:
        if path in seen:
            continue
        seen.add(path)
        unique_files.append(path)

    snippets = []
    for path in unique_files[:4]:
        try:
            contents = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        snippets.append(
            {
                "path": str(path.relative_to(source_dir)).replace("\\", "/"),
                "content": contents[:4000],
            }
        )
    return snippets


def _build_messages(
    state: GraphState,
    vulnerability: Vulnerability,
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
        "vulnerability": vulnerability,
        "context_files": context_files,
        "output_schema": {
            "diff": "string, unified diff relative to package root",
            "rationale": "string, concise explanation of why the patch mitigates the vulnerability",
            "target_files": ["string"],
        },
    }
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_payload)},
    ]


def patch_generation(state: GraphState) -> dict:
    source_dir = state.get("source_dir")
    if not source_dir:
        return _with_error(state, "patch_generation: missing source_dir")

    vulnerabilities = state.get("vulnerabilities", [])
    vulnerability = _pick_target_vulnerability(vulnerabilities)
    if vulnerability is None:
        return _with_error(state, "patch_generation: no vulnerabilities available for patching")

    manifest_path_value = state.get("package_manifest_path")
    manifest_path = Path(manifest_path_value) if manifest_path_value else Path(source_dir) / "package.json"
    if not manifest_path.exists():
        return _with_error(state, f"patch_generation: package manifest not found: {manifest_path}")

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return _with_error(state, "patch_generation: OPENAI_API_KEY is not set")

    model_name = state.get("model_name", "gpt-4.1-mini")
    context_files = _read_context_files(Path(source_dir), manifest_path)

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        messages=_build_messages(state, vulnerability, context_files),
    )

    content = response.choices[0].message.content or ""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        return _with_error(state, f"patch_generation: model returned invalid JSON: {exc}")

    diff = payload.get("diff")
    rationale = payload.get("rationale")
    target_files = payload.get("target_files") or []
    if not isinstance(diff, str) or not diff.strip():
        return _with_error(state, "patch_generation: model response did not contain a diff")
    if not isinstance(rationale, str) or not rationale.strip():
        return _with_error(state, "patch_generation: model response did not contain rationale")
    if not isinstance(target_files, list) or not all(isinstance(item, str) for item in target_files):
        return _with_error(state, "patch_generation: model response contained invalid target_files")

    patch_attempts = list(state.get("patch_attempts", []))
    patch_attempt = PatchAttempt(
        attempt_number=len(patch_attempts) + 1,
        vulnerability_id=vulnerability.get("id", "unknown"),
        diff=diff,
        model_used=model_name,
        rationale=rationale,
        target_files=target_files,
    )
    patch_attempts.append(patch_attempt)

    return {
        "patch_attempts": patch_attempts,
        "current_patch": patch_attempt,
    }
