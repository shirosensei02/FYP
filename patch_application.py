"""
patch_application.py
====================
LangGraph node: **Step 4 - Patch Application (Docker Sandbox)**

Responsibilities
----------------
1. Validate the untouched vulnerable package in Docker as the baseline.
2. Materialise the generated patch in a separate workspace.
3. Repack each workspace and install it into a clean consumer project.
4. Run the same public-entry-point smoke test against both packages.
5. Classify the comparison as no regression, regression, inconclusive, or a
   patched-only pass.
6. Tear down Docker resources and retain patched source for re-scanning.

The node intentionally prints a rich step-by-step trace to stdout so that a
human watching the orchestrator can follow exactly what is happening inside the
sandbox.

GraphState keys consumed
------------------------
- ``package_name``     : str  - npm package name (e.g. "lodash")
- ``package_version``  : str  - version string (e.g. "4.17.15")
- ``source_dir``       : str  - extracted, unmodified package source directory
- ``current_patch``    : PatchAttempt - produced by patch_generation; the
                          ``diff`` field holds either a unified diff or a
                          mapping of ``{filename: full_file_content}`` as a
                          JSON string.

GraphState keys produced
------------------------
- ``sandbox_id``           : str | None   - Docker container ID
- ``sandbox_apply_success``: bool | None  - True only for NO_REGRESSION
- ``baseline_validation``  : ValidationResult - untouched package result
- ``patched_validation``   : ValidationResult - generated patch result
- ``validation``           : ValidationResult - alias for patched_validation
- ``regression_status``    : str - baseline-versus-patched classification
- ``errors``               : list[str]    - appended with any runtime errors
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from pathlib import Path
from typing import Any

from state import GraphState, ValidationResult

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%H:%M:%S",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_IMAGE = os.getenv("PATCH_SANDBOX_BASE_IMAGE", "node:22-bookworm-slim")
SANDBOX_TIMEOUT_SECONDS = int(os.getenv("PATCH_SANDBOX_TIMEOUT_SECONDS", "600"))
DOCKER_BUILD_TIMEOUT = int(os.getenv("PATCH_DOCKER_BUILD_TIMEOUT", "600"))
SANDBOX_MEMORY = os.getenv("PATCH_SANDBOX_MEMORY", "2g")
SANDBOX_CPUS = os.getenv("PATCH_SANDBOX_CPUS", "2")
PATCH_WORKSPACE_ROOT = Path(__file__).resolve().parent / ".workspace" / "patched"


# ===========================================================================
# Internal helpers
# ===========================================================================

def _step(msg: str) -> None:
    """Print a visually distinct step header to stdout."""
    banner = f"\n{'-' * 60}\n  >>  {msg}\n{'-' * 60}"
    print(banner, flush=True)
    logger.info(msg)


def _run(
    cmd: list[str],
    *,
    cwd: str | Path | None = None,
    timeout: int = 60,
    capture: bool = True,
    stream: bool = False,
) -> tuple[int, str, str]:
    """
    Run *cmd* as a subprocess.

    Parameters
    ----------
    cmd     : command + args list
    cwd     : working directory
    timeout : seconds before the process is killed
    capture : return stdout/stderr as strings (default True)
    stream  : also print each output line in real-time (default False)

    Returns
    -------
    (returncode, stdout, stderr)
    """
    import threading

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        def _drain(pipe, store: list[str], label: str) -> None:
            for line in pipe:
                store.append(line)
                if stream:
                    prefix = "    [stderr]" if label == "err" else "    [stdout]"
                    print(f"{prefix} {line}", end="", flush=True)

        t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_lines, "out"))
        t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_lines, "err"))
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            logger.error("Command timed out after %ds: %s", timeout, " ".join(cmd))

        t_out.join()
        t_err.join()

        return proc.returncode, "".join(stdout_lines), "".join(stderr_lines)

    except FileNotFoundError as exc:
        return 1, "", f"Executable not found: {exc}"


# ---------------------------------------------------------------------------
# Step A - Materialise patched files
# ---------------------------------------------------------------------------

def _seed_workspace_from_source(source_dir: str | None, work_dir: Path) -> None:
    """Copy the original package so a unified diff has real files to modify."""
    if not source_dir:
        return

    source_path = Path(source_dir)
    if not source_path.is_dir():
        raise FileNotFoundError(f"package source directory not found: {source_path}")

    _step("A0. Copying original package into sandbox workspace")
    shutil.copytree(
        source_path,
        work_dir,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("node_modules", ".git"),
    )
    print(f"    OK  copied package source from {source_path}", flush=True)

def _split_diff_into_hunks(diff_text: str) -> list[str]:
    """Split a unified diff into standalone single-hunk diffs, each carrying
    its file's ``--- ``/``+++ `` header, in original order.

    Some models produce multi-hunk diffs where several hunks each have a
    slightly wrong header line-count; applying the whole diff in one
    ``git apply`` call can fail even with ``--recount``, but each hunk
    individually (recounted on its own) often still applies cleanly.
    """
    lines = diff_text.splitlines(keepends=True)
    pieces: list[str] = []
    header: list[str] = []
    hunk: list[str] = []

    def flush() -> None:
        if hunk:
            pieces.append("".join(header) + "".join(hunk))

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if line.startswith("--- "):
            flush()
            hunk = []
            header = [line]
            if i + 1 < n and lines[i + 1].startswith("+++ "):
                header.append(lines[i + 1])
                i += 2
                continue
            i += 1
            continue
        if line.startswith("@@"):
            flush()
            hunk = [line]
            i += 1
            continue
        hunk.append(line)
        i += 1
    flush()
    return pieces


def _write_patched_package(
    work_dir: Path,
    package_name: str,
    package_version: str,
    patch: dict[str, Any],
) -> bool:
    """
    Write the patched npm package to *work_dir*.

    The ``diff`` field in a PatchAttempt can arrive in two formats:

    Format 1 - **file-map** (preferred by patch_generation)
        A JSON string whose top-level keys are file paths (relative to the
        package root) and whose values are the *full* replacement file content.
        Example:
            {"package.json": "{ ... }", "index.js": "console.log('hi')"}

    Format 2 - **unified diff**
        A standard ``--- a/ +++ b/`` unified diff string.  We apply it with
        the stdlib ``patch`` module (or fall back to writing a placeholder).

    Returns True if the patched source was successfully written (file-map
    writes always succeed; a unified diff succeeds only if ``patch`` applied
    it cleanly), False otherwise.
    """
    _step("A . Writing patched package files to sandbox workspace")

    diff_raw: str = patch.get("diff", "")

    # --- try Format 1 first ---------------------------------------------------
    try:
        file_map: dict[str, str] = json.loads(diff_raw)
        if isinstance(file_map, dict):
            print(f"    Patch format: file-map ({len(file_map)} files)", flush=True)
            for rel_path, content in file_map.items():
                target = work_dir / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
                print(f"    OK  wrote {rel_path} ({len(content)} bytes)", flush=True)
            return True
    except (json.JSONDecodeError, TypeError):
        pass

    # --- Format 2: unified diff -----------------------------------------------
    print("    Patch format: unified diff", flush=True)

    # A unified diff without a trailing newline makes `patch`/`git apply`
    # misparse the final hunk ("corrupt patch" one line past the last real
    # line) even though the content itself is fine; models frequently omit
    # it when echoing a file's last line back. Appending one is always safe.
    if not diff_raw.endswith("\n"):
        diff_raw += "\n"

    # Write the diff to a file so we can call `patch` CLI
    diff_file = work_dir / "patch_input.diff"
    diff_file.write_text(diff_raw, encoding="utf-8")

    # Snapshot the pristine source on disk (not via git) so a `patch` run
    # that fails partway through (it applies hunks one at a time, so an
    # early hunk can land before a later one fails) can be cleanly rolled
    # back before retrying with a different tool. A plain filesystem copy
    # can't silently no-op the way a git snapshot can if `git` is missing
    # or any of its setup commands fail without us checking their exit code.
    pristine_backup = Path(tempfile.mkdtemp(prefix="pristine_", dir=work_dir.parent))
    shutil.copytree(work_dir, pristine_backup, dirs_exist_ok=True)

    rc, out, err = _run(
        ["patch", "-p1", "--input", str(diff_file)],
        cwd=work_dir,
        timeout=30,
    )
    if rc != 0:
        logger.warning("patch CLI returned %d; trying git apply --recount.\n%s", rc, err)
        print(f"    WARNING  patch exited {rc}: {err.strip()}", flush=True)

        # Roll back any partial changes `patch` made before it failed, so
        # the fallback applies against the original, untouched source.
        shutil.rmtree(work_dir)
        shutil.copytree(pristine_backup, work_dir)

        # `patch` is strict about the hunk header's declared line counts; a
        # model can get the content exactly right but miscount by one, which
        # `patch` rejects outright. `git apply --recount` recomputes those
        # counts from the actual +/-/context lines instead of trusting them.
        git_rc, git_out, git_err = _run(
             ["git", "apply", "--ignore-whitespace", "--unsafe-paths", "--recount", str(diff_file)],
            cwd=work_dir,
            timeout=30,
        )
        if git_rc != 0:
            logger.warning("git apply --recount returned %d; trying hunk-by-hunk.\n%s", git_rc, git_err)
            print(f"    WARNING  git apply --recount exited {git_rc}: {git_err.strip()}", flush=True)

            # Roll back again before the final fallback: applying the whole
            # diff in one shot can fail even with --recount when several
            # hunks each have slightly wrong header counts, but each hunk
            # individually (recounted on its own) often still applies.
            shutil.rmtree(work_dir)
            shutil.copytree(pristine_backup, work_dir)

            hunks = _split_diff_into_hunks(diff_raw)
            hunk_ok = bool(hunks)
            for idx, hunk_diff in enumerate(hunks, start=1):
                hunk_file = work_dir / f"_hunk_{idx}.diff"
                hunk_file.write_text(hunk_diff, encoding="utf-8")
                h_rc, h_out, h_err = _run(
                    ["git", "apply", "--ignore-whitespace", "--unsafe-paths", "--recount", str(hunk_file)],
                    cwd=work_dir,
                    timeout=30,
                )
                hunk_file.unlink(missing_ok=True)
                if h_rc != 0:
                    logger.warning(
                        "hunk %d/%d failed via git apply --recount (rc=%d); aborting attempt.\n%s",
                        idx, len(hunks), h_rc, h_err,
                    )
                    print(f"    FAIL  hunk {idx}/{len(hunks)} exited {h_rc}: {h_err.strip()}", flush=True)
                    hunk_ok = False
                    break

            if not hunk_ok:
                shutil.rmtree(pristine_backup, ignore_errors=True)
                return False
            print(f"    OK  unified diff applied successfully hunk-by-hunk ({len(hunks)} hunks)", flush=True)
        else:
            print("    OK  unified diff applied successfully via git apply --recount", flush=True)
    else:
        print("    OK  unified diff applied successfully", flush=True)
    shutil.rmtree(pristine_backup, ignore_errors=True)

    # Always ensure a minimal package.json exists so npm install won't crash
    pkg_json = work_dir / "package.json"
    if not pkg_json.exists():
        pkg_json.write_text(
            json.dumps(
                {
                    "name": package_name,
                    "version": package_version,
                    "description": "Auto-patched package",
                    "main": "index.js",
                    "scripts": {"test": "echo 'No test specified' && exit 0"},
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print("    OK  generated minimal package.json", flush=True)

    return True


# ---------------------------------------------------------------------------
# Step B - Write Dockerfile
# ---------------------------------------------------------------------------

DOCKERFILE_TEMPLATE = textwrap.dedent(
    """\
    FROM {base_image} AS source
    WORKDIR /package
    RUN if command -v apk >/dev/null 2>&1; then \
          apk add --no-cache git; \
        elif command -v apt-get >/dev/null 2>&1; then \
          apt-get update && apt-get install -y --no-install-recommends git && \
          rm -rf /var/lib/apt/lists/*; \
        fi
    COPY . /package

    FROM source AS installed
    RUN mkdir -p /tmp/package-artifact && \
        tar --exclude=./Dockerfile \
            --exclude=./patch_input.diff \
            --transform='s,^\\./,package/,' \
            -czf /tmp/package-artifact/package.tgz .
    RUN mkdir -p /consumer && \
        cd /consumer && \
        npm init -y && \
        npm install --prefer-offline --omit=dev --no-audit /tmp/package-artifact/*.tgz
    WORKDIR /consumer
    """
)


def _write_dockerfile(work_dir: Path) -> Path:
    """Write a Dockerfile into *work_dir* and return its path."""
    _step("B . Writing Dockerfile into sandbox workspace")

    dockerfile = work_dir / "Dockerfile"
    dockerfile.write_text(
        DOCKERFILE_TEMPLATE.format(base_image=BASE_IMAGE),
        encoding="utf-8",
    )
    print(f"    OK  Dockerfile written ({dockerfile})", flush=True)
    return dockerfile


# ---------------------------------------------------------------------------
# Step C - Build Docker image
# ---------------------------------------------------------------------------

def _build_image(work_dir: Path, image_tag: str, target: str) -> tuple[bool, str]:
    """Build one Docker stage and return ``(success, combined_log)``."""
    _step(f"Building Docker stage {target}  ->  {image_tag}")

    cmd = ["docker", "build", "--target", target, "--tag", image_tag, "."]
    print(f"    $ {' '.join(cmd)}", flush=True)

    rc, out, err = _run(
        cmd,
        cwd=work_dir,
        timeout=DOCKER_BUILD_TIMEOUT,
        stream=True,
    )

    combined = out + err
    if rc == 0:
        print(f"\n    OK  Docker stage {target} built successfully", flush=True)
    else:
        print(f"\n    FAIL  Docker stage {target} failed (exit {rc})", flush=True)

    return rc == 0, combined


def _run_consumer_smoke(
    image_tag: str,
    container_name: str,
    smoke_command: list[str],
) -> tuple[bool, str, str]:
    """Import the installed package from a clean, network-isolated consumer."""
    smoke_shell = shlex.join(smoke_command)
    script = f"{smoke_shell}; smoke_rc=$?; echo __SMOKE_EXIT__:$smoke_rc; exit 0"
    _step("Running published-package consumer smoke test")

    # Start detached
    start_cmd = [
        "docker", "run",
        "--detach",
        "--name", container_name,
        "--network", "none",
        "--memory", SANDBOX_MEMORY,
        "--cpus", SANDBOX_CPUS,
        image_tag,
        "sh", "-c", script,
    ]
    print(f"    $ {' '.join(start_cmd)}", flush=True)

    rc_start, container_id, err_start = _run(start_cmd, timeout=30)
    container_id = container_id.strip()

    if rc_start != 0 or not container_id:
        print(f"    FAIL  Failed to start container: {err_start.strip()}", flush=True)
        return False, "", f"docker run failed: {err_start}"

    print(f"    Container ID: {container_id[:12]}", flush=True)
    print("    Waiting for container to finish ...", flush=True)

    # Poll until container exits (or timeout)
    deadline = time.monotonic() + SANDBOX_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        rc_inspect, inspect_out, _ = _run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container_id],
            timeout=10,
        )
        status = inspect_out.strip()
        if status == "exited":
            break
        print(f"    ... container status: {status}", flush=True)
        time.sleep(3)
    else:
        print("    WARNING  Timeout reached; killing container", flush=True)
        _run(["docker", "kill", container_id], timeout=10)

    # Fetch exit code
    rc_ec, exit_code_str, _ = _run(
        ["docker", "inspect", "--format", "{{.State.ExitCode}}", container_id],
        timeout=10,
    )
    exit_code = int(exit_code_str.strip()) if exit_code_str.strip().lstrip("-").isdigit() else 1

    # Fetch logs
    rc_logs, logs_out, logs_err = _run(
        ["docker", "logs", container_id],
        timeout=30,
        stream=True,
    )
    full_logs = logs_out + logs_err

    smoke_match = re.search(r"__SMOKE_EXIT__:(\d+)", full_logs)
    smoke_ok = exit_code == 0 and bool(smoke_match) and smoke_match.group(1) == "0"
    print(f"\n    Consumer smoke test: {'PASS' if smoke_ok else 'FAIL'}", flush=True)
    return smoke_ok, container_id, full_logs


def _select_validation_commands(work_dir: Path) -> tuple[list[str] | None, list[str]]:
    """Return skipped native build and a public-package import smoke test."""
    try:
        package_json = json.loads((work_dir / "package.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        package_json = {}

    package_name = package_json.get("name")
    if not isinstance(package_name, str) or not package_name.strip():
        package_name = "."
    smoke_script = (
        "const name = process.argv[1]; "
        "const loaded = await import(name); "
        "if (loaded == null) throw new Error('Package import returned no module'); "
        "console.log('Consumer import succeeded:', name);"
    )
    return None, ["node", "--input-type=module", "-e", smoke_script, package_name]


def _validation_succeeded(validation: ValidationResult | None) -> bool:
    if not validation:
        return False
    if validation.get("validation_mode") == "published_package":
        return all(
            validation.get(field) == "PASS"
            for field in ("docker_status", "installation_status", "consumer_smoke_status")
        )
    return all(
        bool(validation.get(field))
        for field in (
            "docker_image_built",
            "install_succeeded",
            "build_succeeded",
            "tests_passed",
        )
    )


def _classify_regression(
    baseline: ValidationResult | None,
    patched: ValidationResult | None,
) -> str:
    baseline_ok = _validation_succeeded(baseline)
    patched_ok = _validation_succeeded(patched)
    if baseline_ok and patched_ok:
        return "NO_REGRESSION"
    if baseline_ok and not patched_ok:
        return "REGRESSION"
    if not baseline_ok and patched_ok:
        return "PATCHED_ONLY_PASS"
    return "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# Step F - Tear-down
# ---------------------------------------------------------------------------

def _teardown(
    container_id: str,
    image_tags: list[str],
) -> None:
    """Remove Docker resources created by one validation run."""
    _step("Tearing down sandbox resources")

    if container_id:
        rc, _, _ = _run(["docker", "rm", "--force", container_id], timeout=20)
        if rc == 0:
            print(f"    OK  Container {container_id[:12]} removed", flush=True)

    for image_tag in image_tags:
        if image_tag:
            rc, _, _ = _run(["docker", "rmi", "--force", image_tag], timeout=30)
            if rc == 0:
                print(f"    OK  Image {image_tag} removed", flush=True)


def _validate_workspace(
    work_dir: Path,
    image_tag: str,
    container_name: str,
) -> ValidationResult:
    """Install and import one package exactly as a published-package consumer.

    The workspace was extracted from an npm tarball, so it already contains
    only published files. Re-archive those files directly instead of invoking
    ``npm pack``, which can run repository-only lifecycle scripts such as
    ``prepare`` even when their source tooling is absent.
    """
    source_tag = f"{image_tag}-source"
    container_id = ""
    logs: list[str] = []
    image_ok = install_ok = smoke_ok = False
    build_command, smoke_command = _select_validation_commands(work_dir)
    smoke_status = "SKIPPED"

    try:
        _write_dockerfile(work_dir)
        image_ok, source_log = _build_image(work_dir, source_tag, "source")
        logs.append("=== docker source stage ===\n" + source_log)
        if image_ok:
            install_ok, install_log = _build_image(work_dir, image_tag, "installed")
            logs.append("=== dependency installation ===\n" + install_log)
        if install_ok:
            smoke_ok, container_id, command_log = _run_consumer_smoke(
                image_tag,
                container_name,
                smoke_command,
            )
            smoke_status = "PASS" if smoke_ok else "FAIL"
            logs.append("=== consumer smoke validation ===\n" + command_log)
    finally:
        _teardown(container_id, [image_tag, source_tag])

    return ValidationResult(
        validation_mode="published_package",
        docker_status="PASS" if image_ok else "FAIL",
        installation_status=("PASS" if install_ok else "FAIL") if image_ok else "SKIPPED",
        build_status="SKIPPED",
        build_reason="Published npm package is validated as a consumer artifact, not a source repository.",
        test_status="SKIPPED",
        test_reason="Repository test assets and project-specific tooling are not guaranteed in npm artifacts.",
        consumer_smoke_status=smoke_status,
        consumer_smoke_succeeded=smoke_ok,
        consumer_smoke_command=smoke_command,
        docker_image_built=image_ok,
        install_succeeded=install_ok,
        build_succeeded=None,
        tests_passed=None,
        build_command=build_command,
        test_command=smoke_command,
        revalidation_scan_clean=False,
        logs="\n".join(logs),
    )


# ===========================================================================
# Public LangGraph node
# ===========================================================================

def patch_application(state: GraphState) -> dict:
    """Validate the original package, then compare it with the patched package."""
    errors: list[str] = list(state.get("errors", []))
    baseline_dir: Path | None = None
    patched_dir: Path | None = None

    # ── Unpack inputs ──────────────────────────────────────────────────────
    package_name: str = state.get("package_name", "unknown-package")
    package_version: str = state.get("package_version", "0.0.0")
    current_patch = state.get("current_patch")
    generation_status = state.get("generation_status")

    print("\n" + "=" * 60, flush=True)
    print(f"  PATCH APPLICATION NODE", flush=True)
    print(f"  Package : {package_name}@{package_version}", flush=True)
    print(f"  Attempt : {(current_patch or {}).get('attempt_number', 1)}", flush=True)
    print("=" * 60, flush=True)

    if generation_status == "failed":
        msg = "patch_application: generation failed; skipping sandbox."
        logger.warning(msg)
        errors.append(msg)
        failed_validation = ValidationResult(
            validation_mode="published_package",
            docker_status="SKIPPED",
            installation_status="SKIPPED",
            build_status="SKIPPED",
            test_status="SKIPPED",
            consumer_smoke_status="SKIPPED",
            consumer_smoke_succeeded=False,
            docker_image_built=False,
            install_succeeded=False,
            build_succeeded=None,
            tests_passed=None,
            revalidation_scan_clean=False,
            logs=msg,
        )
        return {
            "sandbox_id": None,
            "sandbox_apply_success": False,
            "baseline_validation": None,
            "patched_validation": failed_validation,
            "validation": failed_validation,
            "regression_status": "INCONCLUSIVE",
            "errors": errors,
        }

    # ── Unique identifiers for this sandbox run ────────────────────────────
    run_id = uuid.uuid4().hex[:8]
    safe_name = re.sub(r"[^a-z0-9]+", "-", package_name.lower()).strip("-") or "pkg"
    baseline_validation: ValidationResult | None = None
    patched_validation: ValidationResult | None = None

    try:
        # ── A: write files ─────────────────────────────────────────────────
        PATCH_WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
        baseline_dir = Path(
            tempfile.mkdtemp(prefix=f"baseline_{safe_name}_", dir=PATCH_WORKSPACE_ROOT)
        )
        patched_dir = Path(
            tempfile.mkdtemp(prefix=f"patch_{safe_name}_", dir=PATCH_WORKSPACE_ROOT)
        )
        print(f"\n    Baseline workspace: {baseline_dir}", flush=True)
        print(f"    Patched workspace : {patched_dir}", flush=True)

        _seed_workspace_from_source(state.get("source_dir"), baseline_dir)
        shutil.copytree(baseline_dir, patched_dir, dirs_exist_ok=True)

        _step("BASELINE - Validating untouched vulnerable package")
        baseline_validation = _validate_workspace(
            baseline_dir,
            f"patch-sandbox/{safe_name}:{run_id}-baseline",
            f"baseline-{safe_name}-{run_id}",
        )

        patch_applied_ok = _write_patched_package(
            patched_dir,
            package_name,
            package_version,
            current_patch,
        )

        if not patch_applied_ok:
            errors.append("patch failed to apply cleanly; patched validation skipped")
            raise RuntimeError("Patch did not apply to the source")

        # Run the identical validator after applying the generated patch.
        _step("PATCHED - Validating generated patch")
        patched_validation = _validate_workspace(
            patched_dir,
            f"patch-sandbox/{safe_name}:{run_id}-patched",
            f"patch-{safe_name}-{run_id}",
        )

    except Exception as exc:
        msg = f"patch_application error: {type(exc).__name__}: {exc}"
        logger.exception(msg)
        errors.append(msg)
    if patched_validation is None:
        patched_validation = ValidationResult(
            validation_mode="published_package",
            docker_status="FAIL",
            installation_status="SKIPPED",
            build_status="SKIPPED",
            test_status="SKIPPED",
            consumer_smoke_status="SKIPPED",
            consumer_smoke_succeeded=False,
            docker_image_built=False,
            install_succeeded=False,
            build_succeeded=None,
            tests_passed=None,
            revalidation_scan_clean=False,
            logs="Patched validation did not complete.",
        )

    # ── Summarise ──────────────────────────────────────────────────────────
    regression_status = _classify_regression(baseline_validation, patched_validation)
    apply_success = regression_status == "NO_REGRESSION"

    _step("Validation comparison summary")
    print(
        f"    Baseline consumer validation : {'PASS' if _validation_succeeded(baseline_validation) else 'FAIL'}",
        flush=True,
    )
    print(
        f"    Patched consumer validation  : {'PASS' if _validation_succeeded(patched_validation) else 'FAIL'}",
        flush=True,
    )
    print(f"    Regression status   : {regression_status}", flush=True)
    if patched_dir and patched_dir.exists():
        print(f"    Patched source kept : {patched_dir}", flush=True)

    if baseline_dir:
        shutil.rmtree(baseline_dir, ignore_errors=True)

    return {
        "sandbox_id": None,
        "sandbox_apply_success": apply_success,
        "patched_source_dir": str(patched_dir) if patched_dir and patched_dir.exists() else None,
        "baseline_validation": baseline_validation,
        "patched_validation": patched_validation,
        "validation": patched_validation,
        "regression_status": regression_status,
        "errors": errors,
    }
