"""
Shared state that flows through every node in the graph.

LangGraph passes this dict-like object from node to node. Each node
reads what it needs and returns a partial dict of updates, which
LangGraph merges into the running state.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict


class Vulnerability(TypedDict, total=False):
    id: str  # e.g. CVE-2024-12345 / GHSA-xxxx
    severity: str  # low / medium / high / critical
    package: str
    installed_version: str
    fixed_version: str | None
    description: str
    advisory_url: str | None
    scanner: str
    aliases: list[str]


class PatchAttempt(TypedDict, total=False):
    attempt_number: int
    vulnerability_id: str
    diff: str  # unified diff or full file replacement
    model_used: str
    rationale: str
    target_files: list[str]


class ValidationResult(TypedDict, total=False):
    build_succeeded: bool
    tests_passed: bool
    revalidation_scan_clean: bool
    logs: str


class GraphState(TypedDict, total=False):
    # config
    model_name: str  # e.g. "claude-sonnet-4-6" — single model for now,
                      # loop over this in a driver script later for the study

    # 1) input
    package_name: str
    package_version: str
    source_dir: str
    package_manifest_path: str
    tarball_path: str

    # 2) vulnerability detection (syft + grype)
    sbom: dict[str, Any]  # syft output
    vulnerabilities: list[Vulnerability]  # grype output, parsed
    scan_artifacts: dict[str, str]

    # 3) patch generation
    patch_attempts: list[PatchAttempt]
    current_patch: PatchAttempt | None

    # 4) patch application (sandbox)
    sandbox_id: str | None
    sandbox_apply_success: bool | None

    # 5) validation
    validation: ValidationResult | None

    # 6) classification
    classification: Literal["pass", "fail"] | None
    classification_reason: str | None

    # control flow / bookkeeping
    retry_count: int
    max_retries: int
    errors: list[str]
