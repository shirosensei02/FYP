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
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote

import certifi

from state import AnswerKey, GraphState, Vulnerability

GITHUB_API = "https://api.github.com"
OSV_API = "https://api.osv.dev"
REQUEST_TIMEOUT_SECONDS = 20
MAX_COMMITS = 3

_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_COMMIT_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit(?:s)?/(?P<sha>[0-9a-fA-F]{7,40})"
)
_SECTION_CUT = re.compile(
    r"(?im)^#{0,6}\s*(proof of concept|poc|remediation|recommendation|patches|workaround|references)\b.*$"
)
_HEADING = re.compile(r"(?m)^#{1,6}\s+.*$")


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
    token = (os.getenv("GITHUB_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_get(url: str) -> tuple[Any | None, str | None]:
    request = urllib.request.Request(url, headers=_github_headers())
    try:
        with urllib.request.urlopen(
            request, timeout=REQUEST_TIMEOUT_SECONDS,
            context=ssl.create_default_context(cafile=certifi.where()),
        ) as response:
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


def commit_ref_from_url(url: str | None) -> dict[str, str] | None:
    """Return one GitHub commit reference, or None when the URL is not a commit."""
    match = _COMMIT_RE.search(str(url or ""))
    if not match:
        return None
    return {
        "owner": match.group("owner"),
        "repo": match.group("repo"),
        "sha": match.group("sha"),
        "url": match.group(0),
    }


def _patched_version_identifier(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        identifier = value.get("identifier")
        if isinstance(identifier, str) and identifier.strip():
            return identifier.strip()
    return None


def advisory_bug_statement(advisory: dict[str, Any]) -> str | None:
    """Overview prose from a GitHub advisory, without the proof of concept or the fix."""
    description = advisory.get("description")
    if isinstance(description, str) and description.strip():
        text = description.replace("\r\n", "\n").replace("`", "")
        cut = _SECTION_CUT.search(text)
        if cut:
            text = text[: cut.start()]
        text = _HEADING.sub("", text)
        lines = [line.rstrip() for line in text.splitlines()]
        text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
        if text:
            return text
    summary = advisory.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()
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
    github_error = None
    if ghsa_id:
        payload, github_error = _github_get(f"{GITHUB_API}/advisories/{ghsa_id}")
        if isinstance(payload, dict):
            return payload, None
        osv_payload = _fetch_osv_advisory(ghsa_id)
        if osv_payload:
            return osv_payload, None
        if github_error:
            return None, github_error
    if cve_id:
        payload, github_error = _github_get(f"{GITHUB_API}/advisories?cve_id={cve_id}")
        if isinstance(payload, list) and payload:
            return payload[0], None
        if isinstance(payload, dict):
            return payload, None
        osv_payload = _fetch_osv_advisory(cve_id)
        if osv_payload:
            return osv_payload, None
        return None, github_error
    return None, None


def _fetch_osv_advisory(vuln_id: str) -> dict[str, Any] | None:
    """GitHub-shaped advisory from OSV when the GitHub advisory API is unavailable."""
    url = f"{OSV_API}/v1/vulns/{quote(vuln_id, safe='')}"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "fyp-patch-pipeline"},
    )
    try:
        with urllib.request.urlopen(
            request, timeout=REQUEST_TIMEOUT_SECONDS,
            context=ssl.create_default_context(cafile=certifi.where()),
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or not payload.get("id"):
        return None
    return _osv_to_advisory(payload)


def _osv_to_advisory(payload: dict[str, Any]) -> dict[str, Any]:
    aliases = [str(alias) for alias in payload.get("aliases") or []]
    vuln_id = str(payload.get("id") or "")
    ghsa_id = vuln_id if vuln_id.upper().startswith("GHSA-") else None
    cve_id = vuln_id if vuln_id.upper().startswith("CVE-") else None
    for alias in aliases:
        if ghsa_id is None and alias.upper().startswith("GHSA-"):
            ghsa_id = alias
        if cve_id is None and alias.upper().startswith("CVE-"):
            cve_id = alias
    vulnerabilities = []
    for affected in payload.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") if isinstance(affected.get("package"), dict) else {}
        fixed = None
        for version_range in affected.get("ranges") or []:
            if not isinstance(version_range, dict):
                continue
            for event in version_range.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    fixed = str(event["fixed"])
        specific = affected.get("database_specific") if isinstance(affected.get("database_specific"), dict) else {}
        vulnerabilities.append(
            {
                "package": {"ecosystem": package.get("ecosystem"), "name": package.get("name")},
                "vulnerable_version_range": specific.get("last_known_affected_version_range"),
                "first_patched_version": fixed,
            }
        )
    references = [
        ref.get("url")
        for ref in payload.get("references") or []
        if isinstance(ref, dict) and ref.get("url")
    ]
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": payload.get("summary"),
        "description": payload.get("details"),
        "html_url": f"https://github.com/advisories/{ghsa_id}" if ghsa_id else None,
        "references": references,
        "vulnerabilities": vulnerabilities,
    }


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
    user_commit = commit_ref_from_url(state.get("maintainer_commit_url"))
    if not ghsa_id and not cve_id and not user_commit:
        return {"answer_key": empty}

    advisory = None
    error = None
    if ghsa_id or cve_id:
        advisory, error = _fetch_advisory(ghsa_id, cve_id)
        if (error or not advisory) and not user_commit:
            if error:
                empty["status"] = "error"
                empty["summary"] = error
            return {"answer_key": empty}

    if advisory:
        ghsa_id = advisory.get("ghsa_id") or ghsa_id
        cve_id = advisory.get("cve_id") or cve_id
        empty["ghsa_id"] = ghsa_id
        empty["cve_id"] = cve_id
    commit_refs = _extract_commit_refs((advisory or {}).get("references") or [])
    if user_commit:
        user_key = (user_commit["owner"], user_commit["repo"], user_commit["sha"].lower())
        commit_refs = [
            user_commit,
            *[
                ref for ref in commit_refs
                if (ref["owner"], ref["repo"], ref["sha"].lower()) != user_key
            ],
        ]
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

    first_patched = _first_patched_version(advisory, state.get("package_name")) if advisory else None
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
        "advisory_url": f"https://github.com/advisories/{ghsa_id}" if ghsa_id else (advisory or {}).get("html_url"),
        "summary": (advisory_bug_statement(advisory) if advisory else None) or error or fetch_error,
        "commit_refs": commit_refs,
        "files": files,
        "diff": combined_diff,
    }
    return {"answer_key": answer_key}
