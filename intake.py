"""Parse a pipeline prompt and turn a confirmation reply into run fields.

The draft is package@version, an optional suspected issue, and an optional
maintainer commit URL. Confirmation accepts the draft or replaces it.
"""

from __future__ import annotations

import json
import re
from typing import Any

from og_patch_resolution import _COMMIT_RE

PACKAGE_PATTERN = re.compile(r"(@?[A-Za-z0-9][\w.-]*(?:/[\w.-]+)?)@(\d[\w.+-]*)")
ADVISORY_PATTERN = re.compile(r"\b(GHSA(?:-[a-z0-9]{4}){3}|CVE-\d{4}-\d+)\b", re.IGNORECASE)
_MODEL_ALIASES = {"codex", "gpt", "sonnet", "claude"}
_CONFIRM = {"", "confirm", "yes"}


def parse_prompt(text: str) -> dict[str, str]:
    """Read one prompt into the confirmation draft.

    Advisory ids and model names are kept out of the suspected issue. The first
    GitHub commit URL is the maintainer patch link.
    """
    raw = str(text or "")
    draft = {
        "package_name": "",
        "package_version": "",
        "suspected_issue": "",
        "maintainer_commit_url": "",
        "vulnerability_id": "",
        "model_name": "",
        "user_prompt": raw.strip(),
    }
    commit = _COMMIT_RE.search(raw)
    if commit:
        draft["maintainer_commit_url"] = commit.group(0)
    package = PACKAGE_PATTERN.search(raw)
    if package:
        draft["package_name"] = package.group(1)
        draft["package_version"] = package.group(2)
    advisory = ADVISORY_PATTERN.search(raw)
    if advisory:
        draft["vulnerability_id"] = advisory.group(1)

    remainder = raw
    if commit:
        remainder = remainder[:commit.start()] + " " + remainder[commit.end():]
    if package:
        # Search again: removing the commit can shift indexes.
        located = PACKAGE_PATTERN.search(remainder)
        if located:
            remainder = remainder[:located.start()] + " " + remainder[located.end():]
    issue_words = []
    for token in remainder.split():
        cleaned = token.strip(",.;")
        if not cleaned:
            continue
        if ADVISORY_PATTERN.fullmatch(cleaned):
            continue
        if _is_model_token(cleaned) and not draft["model_name"]:
            draft["model_name"] = cleaned.strip(",.")
            continue
        if _is_model_token(cleaned):
            continue
        issue_words.append(cleaned)
    draft["suspected_issue"] = " ".join(issue_words).strip()
    return draft


def format_draft(draft: dict[str, Any]) -> str:
    """The confirmation text shown before the pipeline starts."""
    name = str(draft.get("package_name") or "").strip()
    version = str(draft.get("package_version") or "").strip()
    package = f"{name}@{version}" if name and version else "(missing)"
    issue = str(draft.get("suspected_issue") or "").strip()
    commit = str(draft.get("maintainer_commit_url") or "").strip()
    return "\n".join([
        package,
        f'suspected issue: "{issue}"' if issue else "suspected issue: (none)",
        f"maintainer patch: {commit}" if commit else "maintainer patch: (none)",
        "",
        "Reply confirm to run, or send a corrected prompt.",
    ])


def apply_resume(draft: dict[str, Any], resume: Any) -> dict[str, Any]:
    """Accept the draft, replace its fields, or re-parse a corrected prompt.

    A confirmation without a package and version stays unconfirmed.
    """
    if isinstance(resume, dict):
        merged = _copy_draft(draft)
        for key in ("package_name", "package_version", "suspected_issue", "maintainer_commit_url", "vulnerability_id"):
            if key in resume and resume[key] is not None:
                merged[key] = str(resume[key]).strip()
        confirmed = resume.get("confirm", True) is not False
        return {"confirmed": confirmed and _has_package(merged), "draft": merged}

    text = "" if resume is None else str(resume).strip()
    if text.startswith("{") and text.endswith("}"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            return apply_resume(draft, payload)
    if text.lower() in _CONFIRM:
        current = _copy_draft(draft)
        return {"confirmed": _has_package(current), "draft": current}
    parsed = parse_prompt(text)
    if draft.get("model_name") and not parsed.get("model_name"):
        parsed["model_name"] = str(draft.get("model_name") or "")
    return {"confirmed": False, "draft": parsed}


def confirmed_fields(draft: dict[str, Any]) -> dict[str, Any]:
    """State fields written once the draft is confirmed."""
    return {
        "package_name": str(draft.get("package_name") or "").strip(),
        "package_version": str(draft.get("package_version") or "").strip(),
        "suspected_issue": str(draft.get("suspected_issue") or "").strip(),
        "maintainer_commit_url": str(draft.get("maintainer_commit_url") or "").strip(),
        "intake_confirmed": True,
    }


def _copy_draft(draft: dict[str, Any]) -> dict[str, str]:
    return {key: str(draft.get(key) or "") for key in (
        "package_name", "package_version", "suspected_issue", "maintainer_commit_url",
        "vulnerability_id", "model_name", "user_prompt",
    )}


def _has_package(draft: dict[str, Any]) -> bool:
    return bool(str(draft.get("package_name") or "").strip() and str(draft.get("package_version") or "").strip())


def _is_model_token(token: str) -> bool:
    lowered = token.lower().strip(",.")
    if lowered in _MODEL_ALIASES:
        return True
    return "/" in lowered and not lowered.startswith("http")
