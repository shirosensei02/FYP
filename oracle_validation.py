"""Validate a generated oracle against vulnerable, fixed, and AI-patched code."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import uuid
from pathlib import Path
from typing import Any

from patch_application import BASE_IMAGE, _write_patched_package
from state import (
    GeneratedPatchOracleResult,
    GraphState,
    OracleExecutionResult,
    OracleValidationResult,
)


ORACLE_WORKSPACE_ROOT = Path(__file__).resolve().parent / ".workspace" / "oracles"
ORACLE_BUILD_TIMEOUT = int(os.getenv("ORACLE_DOCKER_BUILD_TIMEOUT", "600"))
ORACLE_MEMORY = os.getenv("ORACLE_SANDBOX_MEMORY", "512m")
ORACLE_CPUS = os.getenv("ORACLE_SANDBOX_CPUS", "1")
MAX_CAPTURE_CHARS = 40_000
_RESULT_RE = re.compile(r"^ORACLE_RESULT\s+(.+)$", re.MULTILINE)

_DOCKERFILE = textwrap.dedent(
    r"""FROM {base_image}
    {fixture_install}
    WORKDIR /package
    COPY package/ /package/
    RUN mkdir -p /tmp/package-artifact && \
        tar --exclude=./node_modules --exclude=./.git \
            --transform='s,^\./,package/,' \
            -czf /tmp/package-artifact/package.tgz . && \
        mkdir -p /consumer && cd /consumer && \
        printf '%s\n' '{{"name":"oracle-consumer","version":"1.0.0","private":true}}' > package.json && \
        npm install --ignore-scripts --omit=dev --no-audit /tmp/package-artifact/package.tgz
    COPY oracle.js /consumer/oracle.js
    COPY oracle-entrypoint.sh /consumer/oracle-entrypoint.sh
    WORKDIR /consumer
    CMD ["sh", "/consumer/oracle-entrypoint.sh"]
    """
)

_GIT_INSTALL = r"""RUN if command -v apk >/dev/null 2>&1; then \
        apk add --no-cache git; \
      elif command -v apt-get >/dev/null 2>&1; then \
        apt-get update && apt-get install -y --no-install-recommends git && \
        rm -rf /var/lib/apt/lists/*; \
      else echo 'Unsupported base image: Git cannot be installed' >&2; exit 1; fi"""

_BASIC_ENTRYPOINT = "#!/bin/sh\nset -eu\nexec node /consumer/oracle.js\n"
_GIT_ENTRYPOINT = """#!/bin/sh
set -eu
repository=/tmp/oracle-repository
mkdir -p "$repository"
cd "$repository"
printf '%s\n' '{"name":"oracle-fixture","version":"1.0.0","private":true}' > package.json
git init -q
git config user.email oracle@example.invalid
git config user.name "Security Oracle"
git add package.json
git commit -qm "oracle fixture"
exec node /consumer/oracle.js
"""


def _execution(
    status: str,
    *,
    operation_completed: bool = False,
    exploit_succeeded: bool | None = None,
    evidence: str = "",
    exit_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
    failure_kind: str | None = None,
) -> OracleExecutionResult:
    return OracleExecutionResult(
        status=status,
        operation_completed=operation_completed,
        exploit_succeeded=exploit_succeeded,
        evidence=evidence,
        exit_code=exit_code,
        stdout=stdout[-MAX_CAPTURE_CHARS:],
        stderr=stderr[-MAX_CAPTURE_CHARS:],
        timed_out=timed_out,
        failure_kind=failure_kind,
    )


def _safe_extract(archive_path: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(archive_path, "r:gz") as archive:
        members = []
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                continue
            if target == root or str(target).startswith(str(root) + os.sep):
                members.append(member)
        archive.extractall(destination, members=members)
    package = destination / "package"
    return package if package.is_dir() else destination


def _copy_package(source: Path, destination: Path) -> None:
    shutil.copytree(
        source,
        destination,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("node_modules", ".git"),
    )


def _best_effort(command: list[str], timeout: int) -> None:
    try:
        subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass


def _env_true(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _oracle_environment(oracle: dict[str, Any]) -> tuple[str, str]:
    """Render only harness-owned setup selected from declared fixture names."""
    requirements = set(oracle.get("requirements") or [])
    fixture_install = _GIT_INSTALL if "requires_git_repository" in requirements else ""
    entrypoint = _GIT_ENTRYPOINT if "requires_git_repository" in requirements else _BASIC_ENTRYPOINT
    if "requires_writable_tmp" in requirements and "requires_git_repository" not in requirements:
        entrypoint = entrypoint.replace(
            "set -eu\n", "set -eu\nmkdir -p /tmp/oracle-workspace\ncd /tmp/oracle-workspace\n", 1
        )
    if "requires_fixture_files" in requirements:
        entrypoint = entrypoint.replace(
            "set -eu\n", "set -eu\nmkdir -p /tmp/oracle-fixtures\n", 1
        )
    return _DOCKERFILE.format(base_image=BASE_IMAGE, fixture_install=fixture_install), entrypoint


def _write_diagnostic(context: Path, name: str, value: str) -> None:
    if _env_true("ORACLE_KEEP_FAILED"):
        (context / name).write_text(value, encoding="utf-8", errors="replace")


def _failure_guidance(*executions: OracleExecutionResult | None) -> list[str]:
    """Turn common prerequisite failures into bounded, actionable retry hints."""
    combined = "\n".join(
        f"{item.get('evidence', '')}\n{item.get('stdout', '')}\n{item.get('stderr', '')}"
        for item in executions if item
    ).lower()
    hints: list[str] = []
    if "cannot find module" in combined or "module_not_found" in combined:
        hints.append("Package resolution failed: require the package normally from /consumer; do not use /oracle paths.")
    git_missing = (
        "git: not found" in combined
        or "git executable" in combined
        or re.search(r"(?:spawn|exec(?:file)?)\s+git\s+enoent", combined) is not None
        or re.search(r"enoent[^\n]{0,120}(?:/|\\)git(?:\.exe)?\b", combined) is not None
    )
    if git_missing:
        hints.append("Git executable missing: declare requires_git_repository.")
    if "not a git repository" in combined or "not have any commits" in combined or "bad revision 'head'" in combined:
        hints.append("Git repository prerequisite failed: declare requires_git_repository and run the API from the supplied repository.")
    if "permission denied" in combined or "read-only file system" in combined:
        hints.append("Write only beneath /tmp; declare requires_writable_tmp to start in a harness-provided writable working directory.")
    return hints


def _run_oracle(source_dir: Path, oracle: dict[str, Any], label: str) -> OracleExecutionResult:
    """Build an image, then execute only the oracle under strict runtime limits."""
    run_id = uuid.uuid4().hex[:12]
    safe_label = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-") or "oracle"
    image = f"fyp-oracle-{safe_label}:{run_id}"
    container = f"fyp-oracle-{safe_label}-{run_id}"
    ORACLE_WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    context = Path(tempfile.mkdtemp(prefix=f"{safe_label}_", dir=ORACLE_WORKSPACE_ROOT))
    execution_completed = False
    try:
        _copy_package(source_dir, context / "package")
        (context / "oracle.js").write_text(str(oracle.get("source") or ""), encoding="utf-8")
        dockerfile, entrypoint = _oracle_environment(oracle)
        (context / "Dockerfile").write_text(dockerfile, encoding="utf-8")
        (context / "oracle-entrypoint.sh").write_text(entrypoint, encoding="utf-8")
        if _env_true("ORACLE_KEEP_FAILED"):
            (context / "attempt.json").write_text(json.dumps({
                "label": label,
                "attempt_number": oracle.get("attempt_number"),
                "requirements": oracle.get("requirements") or [],
            }, indent=2), encoding="utf-8")
        try:
            build = subprocess.run(
                ["docker", "build", "--tag", image, "."],
                cwd=context,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=ORACLE_BUILD_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            _write_diagnostic(context, "build.stdout.txt", str(exc.stdout or ""))
            _write_diagnostic(context, "build.stderr.txt", str(exc.stderr or ""))
            return _execution(
                "INFRA_ERROR", evidence="Docker image build timed out.",
                stdout=str(exc.stdout or ""), stderr=str(exc.stderr or ""), timed_out=True,
                failure_kind="infrastructure",
            )
        except FileNotFoundError as exc:
            return _execution(
                "INFRA_ERROR", evidence=f"Docker is unavailable: {exc}",
                failure_kind="infrastructure",
            )
        if build.returncode != 0:
            _write_diagnostic(context, "build.stdout.txt", build.stdout)
            _write_diagnostic(context, "build.stderr.txt", build.stderr)
            return _execution(
                "INFRA_ERROR", evidence="Docker image build failed.", exit_code=build.returncode,
                stdout=build.stdout, stderr=build.stderr, failure_kind="infrastructure",
            )

        timeout = max(1, min(int(oracle.get("timeout_seconds") or 30), 60))
        command = [
            "docker", "run", "--rm", "--name", container,
            "--network", "none", "--read-only",
            "--user", "node",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "64", "--memory", ORACLE_MEMORY, "--cpus", ORACLE_CPUS,
            image,
        ]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            _best_effort(["docker", "rm", "--force", container], 15)
            return _execution(
                "TIMEOUT", evidence=f"Oracle exceeded {timeout}s timeout.",
                stdout=str(exc.stdout or ""), stderr=str(exc.stderr or ""), timed_out=True,
                failure_kind="operation",
            )
        except (FileNotFoundError, OSError) as exc:
            return _execution(
                "INFRA_ERROR", evidence=f"Docker run could not start: {exc}",
                failure_kind="infrastructure",
            )
        _write_diagnostic(context, "runtime.stdout.txt", completed.stdout)
        _write_diagnostic(context, "runtime.stderr.txt", completed.stderr)
        matches = _RESULT_RE.findall(completed.stdout)
        if not matches:
            if completed.returncode == 125:
                return _execution(
                    "INFRA_ERROR", evidence="Docker could not start the oracle container.",
                    exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
                    failure_kind="infrastructure",
                )
            if completed.returncode == 137:
                return _execution(
                    "INCONCLUSIVE", evidence="Oracle container was killed, possibly by its memory limit.",
                    exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
                    failure_kind="resource",
                )
            if completed.returncode != 0:
                return _execution(
                    "OPERATION_FAILED", evidence="Oracle process exited without a valid result.",
                    exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
                    failure_kind="operation",
                )
            return _execution(
                "INCONCLUSIVE", evidence="Oracle did not emit an ORACLE_RESULT line.",
                exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
                failure_kind="protocol",
            )
        try:
            payload = json.loads(matches[-1])
        except json.JSONDecodeError as exc:
            return _execution(
                "INCONCLUSIVE", evidence=f"Malformed ORACLE_RESULT JSON: {exc}",
                exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
                failure_kind="protocol",
            )
        operation = payload.get("operation_completed")
        exploit = payload.get("exploit_succeeded")
        evidence = str(payload.get("evidence") or "")
        if not isinstance(operation, bool) or not isinstance(exploit, bool):
            return _execution(
                "INCONCLUSIVE", evidence="ORACLE_RESULT booleans are missing or invalid.",
                exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
                failure_kind="protocol",
            )
        if not operation:
            return _execution(
                "OPERATION_FAILED", operation_completed=False, exploit_succeeded=exploit,
                evidence=evidence or "Target package operation did not complete.",
                exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
                failure_kind="operation",
            )
        execution_completed = True
        return _execution(
            "EXPLOIT_SUCCEEDED" if exploit else "EXPLOIT_BLOCKED",
            operation_completed=True, exploit_succeeded=exploit, evidence=evidence,
            exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
        )
    finally:
        _best_effort(["docker", "rm", "--force", container], 15)
        _best_effort(["docker", "image", "rm", "--force", image], 30)
        if not _env_true("ORACLE_KEEP_FAILED") or execution_completed:
            shutil.rmtree(context, ignore_errors=True)


def _prepare_fixed_workspace(state: GraphState, parent: Path) -> tuple[Path | None, str | None]:
    answer = state.get("answer_key") or {}
    source = Path(str(state.get("source_dir") or ""))
    diff = answer.get("diff")
    version = answer.get("first_patched_version")
    package_name = state.get("package_name")
    pack_error: str | None = None

    # Prefer the artifact consumers actually install. A source diff can apply
    # only to unused src/ files while the published runtime loads built dist/.
    if version and package_name:
        packed = parent / "packed"
        packed.mkdir(parents=True, exist_ok=True)
        npm_executable = shutil.which("npm.cmd") or shutil.which("npm")
        if npm_executable:
            try:
                result = subprocess.run(
                    [npm_executable, "pack", f"{package_name}@{version}", "--pack-destination", str(packed)],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=120, check=False,
                )
                archives = sorted(
                    packed.glob("*.tgz"), key=lambda item: item.stat().st_mtime, reverse=True
                )
                if result.returncode == 0 and archives:
                    return _safe_extract(archives[0], parent / "fixed-extracted"), None
                pack_error = f"npm pack for fixed version failed: {result.stderr[-2000:]}"
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
                pack_error = f"Could not obtain fixed npm package: {exc}"
        else:
            pack_error = "npm is not installed or not on PATH"

    if diff:
        fixed = parent / "fixed"
        _copy_package(source, fixed)
        applied = _write_patched_package(
            fixed,
            str(state.get("package_name") or "package"),
            str(answer.get("first_patched_version") or state.get("package_version") or "0.0.0"),
            {"diff": diff},
        )
        if applied:
            return fixed, None
        diff_error = "Maintainer diff did not apply to vulnerable package."
        return None, f"{pack_error}; {diff_error}" if pack_error else diff_error

    return None, pack_error or "No maintainer diff or fixed version is available."


def _append_attempt_validation(state: GraphState, result: OracleValidationResult) -> list[dict[str, Any]]:
    attempts = list(state.get("oracle_attempts") or [])
    if attempts:
        attempts[-1] = {**attempts[-1], "validation": dict(result)}
    return attempts


def oracle_validation(state: GraphState) -> dict:
    candidate = state.get("oracle_candidate") or {}
    candidate_status = candidate.get("status")
    if candidate_status == "skipped":
        result = OracleValidationResult(status="SKIPPED", reason=candidate.get("explanation") or "Skipped.", vulnerable=None, fixed=None)
        return {"oracle_validation": result, "oracle_attempts": _append_attempt_validation(state, result)}
    if candidate_status == "invalid":
        result = OracleValidationResult(status="INVALID", reason=candidate.get("explanation") or "Oracle candidate is invalid.", vulnerable=None, fixed=None)
        return {
            "oracle_validation": result,
            "oracle_attempts": _append_attempt_validation(state, result),
            "oracle_feedback": dict(result),
        }
    if candidate_status != "generated":
        result = OracleValidationResult(status="ERROR", reason=candidate.get("explanation") or "Oracle generation failed.", vulnerable=None, fixed=None)
        return {"oracle_validation": result, "oracle_attempts": _append_attempt_validation(state, result)}

    source = Path(str(state.get("source_dir") or ""))
    if not source.is_dir():
        result = OracleValidationResult(status="ERROR", reason="Vulnerable source directory is unavailable.", vulnerable=None, fixed=None)
        return {"oracle_validation": result, "oracle_attempts": _append_attempt_validation(state, result)}

    ORACLE_WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    parent = Path(tempfile.mkdtemp(prefix="fixed_", dir=ORACLE_WORKSPACE_ROOT))
    try:
        fixed, fixed_error = _prepare_fixed_workspace(state, parent)
        if fixed is None:
            result = OracleValidationResult(status="ERROR", reason=fixed_error or "Fixed baseline unavailable.", vulnerable=None, fixed=None)
        else:
            vulnerable_result = _run_oracle(source, candidate, "vulnerable")
            # Do not spend another build/run after Docker has already proved
            # that the environment, rather than the candidate, is broken.
            fixed_result = (
                None
                if vulnerable_result.get("status") == "INFRA_ERROR"
                else _run_oracle(fixed, candidate, "maintainer-fixed")
            )
            infrastructure_failed = any(
                item.get("status") == "INFRA_ERROR"
                for item in (vulnerable_result, fixed_result)
                if item is not None
            )
            valid = (
                vulnerable_result.get("status") == "EXPLOIT_SUCCEEDED"
                and fixed_result is not None
                and fixed_result.get("status") == "EXPLOIT_BLOCKED"
            )
            fixed_status = fixed_result.get("status") if fixed_result else "NOT_RUN"
            reason = (
                "Oracle reproduced the vulnerability and detected the maintainer fix."
                if valid else
                f"Expected vulnerable=EXPLOIT_SUCCEEDED and fixed=EXPLOIT_BLOCKED; got "
                f"vulnerable={vulnerable_result.get('status')} and fixed={fixed_status}."
            )
            guidance = _failure_guidance(vulnerable_result, fixed_result)
            result = OracleValidationResult(
                status="ERROR" if infrastructure_failed else ("VALID" if valid else "INVALID"),
                reason=("Oracle infrastructure failed; baseline validation was not attempted again. " + reason)
                if infrastructure_failed else reason,
                vulnerable=vulnerable_result, fixed=fixed_result,
                guidance=guidance,
            )
    finally:
        shutil.rmtree(parent, ignore_errors=True)

    update: dict[str, Any] = {
        "oracle_validation": result,
        "oracle_attempts": _append_attempt_validation(state, result),
    }
    if result.get("status") == "VALID":
        accepted = dict(candidate)
        accepted["status"] = "accepted"
        update["accepted_oracle"] = accepted
        update["oracle_feedback"] = None
    elif result.get("status") == "INVALID":
        update["oracle_feedback"] = dict(result)
    return update


def generated_patch_oracle_validation(state: GraphState) -> dict:
    oracle = state.get("accepted_oracle")
    patched = Path(str(state.get("patched_source_dir") or ""))
    if not oracle:
        result = GeneratedPatchOracleResult(status="SKIPPED", reason="No accepted oracle is available.", execution=None)
    elif state.get("patch_applied") is not True:
        result = GeneratedPatchOracleResult(status="SKIPPED", reason="Generated patch did not apply cleanly; oracle execution was skipped.", execution=None)
    elif not patched.is_dir():
        result = GeneratedPatchOracleResult(status="INCONCLUSIVE", reason="Patched source directory is unavailable.", execution=None)
    else:
        execution = _run_oracle(patched, oracle, "generated-patch")
        execution_status = execution.get("status")
        if execution_status == "EXPLOIT_BLOCKED":
            status, reason = "SECURITY_PASS", "Relevant operation completed and the exploit was blocked."
        elif execution_status == "EXPLOIT_SUCCEEDED":
            status, reason = "SECURITY_FAIL", "The accepted exploit still succeeds against the generated patch."
        elif execution_status == "OPERATION_FAILED":
            status, reason = "REGRESSION", "The exploit did not succeed, but the relevant package operation failed."
        else:
            status, reason = "INCONCLUSIVE", f"Oracle execution ended as {execution_status}."
        result = GeneratedPatchOracleResult(status=status, reason=reason, execution=execution)
    return {"generated_patch_oracle_validation": result}
