"""
LangGraph node: resolve the official / vendor patch (answer key) from GitHub Advisory.

Looks up GHSA/CVE on GitHub Advisory and, if a referenced commit exists,
records the maintainer file list and unified diff as the answer key.

This node must not be read by patch_generation.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from state import AnswerKey, GraphState, Vulnerability

GITHUB_API = "https://api.github.com"
REQUEST_TIMEOUT_SECONDS = 20
MAX_COMMITS = 3

_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_COMMIT_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit(?:s)?/(?P<sha>[0-9a-fA-F]{7,40})"
)


def _collect_ids(vulnerabilities: list[Vulnerability]) -> tuple[str | None, str | None]:
    ghsa_id = None
    cve_id = None
    for item in vulnerabilities:
        tokens = [item.get("id"), item.get("advisory_url"), *(item.get("aliases") or [])]
        for token in tokens:
            if not token:
                continue
            if ghsa_id is None:
                match = _GHSA_RE.search(str(token))
                if match:
                    ghsa_id = "GHSA-" + match.group(0).split("-", 1)[1].lower()
            if cve_id is None:
                match = _CVE_RE.search(str(token))
                if match:
                    cve_id = match.group(0).upper()
        if ghsa_id and cve_id:
            break
    return ghsa_id, cve_id


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "fyp-patch-pipeline",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_get(url: str) -> tuple[Any | None, str | None]:
    request = urllib.request.Request(url, headers=_github_headers())
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        return None, f"GitHub API {exc.code} for {url}"
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return None, f"GitHub API request failed: {exc}"


def _extract_commit_refs(references: list[Any]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    seen = set()
    for reference in references:
        url = reference if isinstance(reference, str) else (reference or {}).get("url")
        if not url:
            continue
        match = _COMMIT_RE.search(str(url))
        if not match:
            continue
        key = (match.group("owner"), match.group("repo"), match.group("sha").lower())
        if key in seen:
            continue
        seen.add(key)
        refs.append(
            {
                "owner": match.group("owner"),
                "repo": match.group("repo"),
                "sha": match.group("sha"),
                "url": str(url),
            }
        )
    return refs


def _patched_version_identifier(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        identifier = value.get("identifier")
        if isinstance(identifier, str) and identifier.strip():
            return identifier.strip()
    return None


def _first_patched_version(advisory: dict[str, Any], package_name: str | None) -> str | None:
    entries = advisory.get("vulnerabilities") or []
    preferred = None
    fallback = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        identifier = _patched_version_identifier(entry.get("first_patched_version"))
        if not identifier:
            continue
        fallback = fallback or identifier
        pkg = (entry.get("package") or {}).get("name") if isinstance(entry.get("package"), dict) else None
        if package_name and pkg and pkg.lower() == package_name.lower():
            preferred = identifier
            break
    return preferred or fallback


def _fetch_advisory(ghsa_id: str | None, cve_id: str | None) -> tuple[dict[str, Any] | None, str | None]:
    if ghsa_id:
        payload, error = _github_get(f"{GITHUB_API}/advisories/{ghsa_id}")
        if isinstance(payload, dict):
            return payload, None
        if error:
            return None, error
    if cve_id:
        payload, error = _github_get(f"{GITHUB_API}/advisories?cve_id={cve_id}")
        if isinstance(payload, list) and payload:
            return payload[0], None
        if isinstance(payload, dict):
            return payload, None
        return None, error
    return None, None


def _commit_payload_to_diff(payload: dict[str, Any]) -> tuple[list[str], str]:
    files: list[str] = []
    parts: list[str] = []
    for item in payload.get("files") or []:
        filename = item.get("filename")
        if not filename:
            continue
        path = str(filename).replace("\\", "/")
        files.append(path)
        parts.append(f"--- a/{path}\n+++ b/{path}\n")
        patch = item.get("patch")
        if patch:
            parts.append(patch if str(patch).endswith("\n") else f"{patch}\n")
    return files, "".join(parts)


def _fetch_commit(commit_ref: dict[str, str]) -> tuple[list[str], str, str | None]:
    url = f"{GITHUB_API}/repos/{commit_ref['owner']}/{commit_ref['repo']}/commits/{commit_ref['sha']}"
    payload, error = _github_get(url)
    if error or not isinstance(payload, dict):
        return [], "", error
    files, diff = _commit_payload_to_diff(payload)
    return files, diff, None


def og_patch_resolution(state: GraphState) -> dict:
    vulnerabilities = state.get("current_vulnerabilities") or state.get("vulnerabilities") or []
    ghsa_id, cve_id = _collect_ids(vulnerabilities)

    empty: AnswerKey = {
        "status": "unavailable",
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "first_patched_version": None,
        "advisory_url": None,
        "summary": None,
        "commit_refs": [],
        "files": [],
        "diff": None,
    }
    if not ghsa_id and not cve_id:
        return {"answer_key": empty}

    advisory, error = _fetch_advisory(ghsa_id, cve_id)
    if error:
        empty["status"] = "error"
        empty["summary"] = error
        return {"answer_key": empty}
    if not advisory:
        return {"answer_key": empty}

    ghsa_id = advisory.get("ghsa_id") or ghsa_id
    cve_id = advisory.get("cve_id") or cve_id
    commit_refs = _extract_commit_refs(advisory.get("references") or [])
    files: list[str] = []
    diffs: list[str] = []
    fetch_error = None
    for commit_ref in commit_refs[:MAX_COMMITS]:
        commit_files, commit_diff, commit_error = _fetch_commit(commit_ref)
        if commit_error and not commit_files and not commit_diff:
            fetch_error = commit_error
            continue
        for path in commit_files:
            if path not in files:
                files.append(path)
        if commit_diff:
            diffs.append(commit_diff)
    combined_diff = "\n".join(diffs) if diffs else None

    first_patched = _first_patched_version(advisory, state.get("package_name"))
    if not first_patched and vulnerabilities:
        first_patched = vulnerabilities[0].get("fixed_version")

    if files or combined_diff:
        status = "resolved"
    elif first_patched:
        status = "version_only"
    elif fetch_error:
        status = "error"
    else:
        status = "unavailable"

    answer_key: AnswerKey = {
        "status": status,
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "first_patched_version": first_patched,
        "advisory_url": f"https://github.com/advisories/{ghsa_id}" if ghsa_id else advisory.get("html_url"),
        "summary": advisory.get("summary") or fetch_error,
        "commit_refs": commit_refs,
        "files": files,
        "diff": combined_diff,
    }
    return {"answer_key": answer_key}
