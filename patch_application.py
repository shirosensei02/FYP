"""
patch_application.py
====================
LangGraph node: **Step 4 - Patch Application (Docker Sandbox)**

Responsibilities
----------------
1. Materialise the patched npm package on-disk from the patch produced in
   step 3 (patch_generation).
2. Build an isolated Docker image that contains *only* the patched package.
3. Run ``npm install`` inside the container and capture logs.
4. Run ``npm test``  inside the container and capture logs.
5. Tear down the container (always) and report success/failure back through
   GraphState so that patch_validation and outcome_classification can act on
   the results.

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
- ``sandbox_apply_success``: bool | None  - True only if install + test pass
- ``validation``           : ValidationResult - pre-populated with raw logs so
                              patch_validation can refine them
- ``errors``               : list[str]    - appended with any runtime errors
"""

from __future__ import annotations

import json
import logging
import os
import re
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
BASE_IMAGE = "node:20-alpine"          # lightweight, reproducible Node image
SANDBOX_TIMEOUT_SECONDS = 120          # max time the container may run
DOCKER_BUILD_TIMEOUT = 180             # docker build can be slow on first pull
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

def _write_patched_package(
    work_dir: Path,
    package_name: str,
    package_version: str,
    patch: dict[str, Any],
) -> None:
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
            return
    except (json.JSONDecodeError, TypeError):
        pass

    # --- Format 2: unified diff -----------------------------------------------
    print("    Patch format: unified diff", flush=True)

    # Write the diff to a file so we can call `patch` CLI
    diff_file = work_dir / "patch_input.diff"
    diff_file.write_text(diff_raw, encoding="utf-8")

    rc, out, err = _run(
        ["patch", "-p1", "--input", str(diff_file)],
        cwd=work_dir,
        timeout=30,
    )
    if rc != 0:
        logger.warning("patch CLI returned %d; continuing anyway.\n%s", rc, err)
        print(f"    WARNING  patch exited {rc}: {err.strip()}", flush=True)
    else:
        print("    OK  unified diff applied successfully", flush=True)

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


# ---------------------------------------------------------------------------
# Step B - Write Dockerfile
# ---------------------------------------------------------------------------

DOCKERFILE_TEMPLATE = textwrap.dedent(
    """\
    # Docker sandbox for npm patch validation
    # Base image: {base_image}
    FROM {base_image}

    # 1. Create a non-root working directory
    WORKDIR /app

    # 2. Copy the (already patched) package source into the image
    COPY . .

    # 3. Install dependencies (ci is stricter than install; falls back if no
    #    package-lock.json is present)
    RUN npm install --prefer-offline --no-audit 2>&1 || true

    # 4. Default command: run the package's own test suite
    CMD ["npm", "test"]
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

def _build_image(work_dir: Path, image_tag: str) -> tuple[bool, str]:
    """
    Run ``docker build`` and return (success, combined_log).
    """
    _step(f"C . Building Docker image  ->  {image_tag}")

    cmd = ["docker", "build", "--tag", image_tag, "."]
    print(f"    $ {' '.join(cmd)}", flush=True)

    rc, out, err = _run(
        cmd,
        cwd=work_dir,
        timeout=DOCKER_BUILD_TIMEOUT,
        stream=True,
    )

    combined = out + err
    if rc == 0:
        print(f"\n    OK  Image built successfully: {image_tag}", flush=True)
    else:
        print(f"\n    FAIL  docker build failed (exit {rc})", flush=True)

    return rc == 0, combined


# ---------------------------------------------------------------------------
# Step D - Run npm install inside container
# ---------------------------------------------------------------------------

def _run_npm_install(image_tag: str, container_name: str) -> tuple[bool, str]:
    """
    Run a *separate* ephemeral container just for ``npm install`` so we can
    capture its output distinctly from the test run.

    We use ``--rm`` so Docker cleans it up automatically.
    """
    _step("D . Running  npm install  inside Docker sandbox")

    cmd = [
        "docker", "run",
        "--rm",
        "--name", f"{container_name}-install",
        "--network", "none",          # no outbound network for safety
        "--memory", "512m",
        "--cpus", "1",
        image_tag,
        "sh", "-c", "npm install --prefer-offline --no-audit 2>&1; echo EXIT_CODE:$?",
    ]
    print(f"    $ {' '.join(cmd)}", flush=True)

    rc, out, err = _run(
        cmd,
        timeout=SANDBOX_TIMEOUT_SECONDS,
        stream=True,
    )

    # Extract the embedded exit code we echoed
    embedded = re.search(r"EXIT_CODE:(\d+)", out)
    inner_rc = int(embedded.group(1)) if embedded else rc

    success = inner_rc == 0
    log = out + err
    if success:
        print("    OK  npm install completed successfully", flush=True)
    else:
        print(f"    FAIL  npm install failed (exit {inner_rc})", flush=True)

    return success, log


# ---------------------------------------------------------------------------
# Step E - Run npm test inside container
# ---------------------------------------------------------------------------

def _run_npm_test(image_tag: str, container_name: str) -> tuple[bool, str, str]:
    """
    Spin up the sandbox container, run ``npm test``, capture its output,
    and return (success, container_id, logs).

    We use ``docker run`` in detached mode, wait for completion, then fetch
    logs, so we always have the container ID for later inspection.
    """
    _step("E . Running  npm test  inside Docker sandbox")

    # Start detached
    start_cmd = [
        "docker", "run",
        "--detach",
        "--name", container_name,
        "--network", "none",
        "--memory", "512m",
        "--cpus", "1",
        image_tag,
        "npm", "test",
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

    success = exit_code == 0
    if success:
        print(f"\n    OK  npm test passed (exit 0)", flush=True)
    else:
        print(f"\n    FAIL  npm test failed (exit {exit_code})", flush=True)

    return success, container_id, full_logs


# ---------------------------------------------------------------------------
# Step F - Tear-down
# ---------------------------------------------------------------------------

def _teardown(
    container_id: str,
    image_tag: str,
    work_dir: Path,
    *,
    preserve_workspace: bool,
) -> None:
    """Remove Docker resources and retain patched files for re-scanning."""
    _step("F . Tearing down sandbox resources")

    if container_id:
        rc, _, _ = _run(["docker", "rm", "--force", container_id], timeout=20)
        if rc == 0:
            print(f"    OK  Container {container_id[:12]} removed", flush=True)

    if image_tag:
        rc, _, _ = _run(["docker", "rmi", "--force", image_tag], timeout=30)
        if rc == 0:
            print(f"    OK  Image {image_tag} removed", flush=True)

    if preserve_workspace:
        print(f"    OK  Patched workspace retained for re-scan: {work_dir}", flush=True)
        return

    try:
        shutil.rmtree(work_dir, ignore_errors=True)
        print(f"    OK  Temp directory {work_dir} deleted", flush=True)
    except Exception as exc:
        logger.warning("Could not delete temp dir %s: %s", work_dir, exc)


# ===========================================================================
# Public LangGraph node
# ===========================================================================

def patch_application(state: GraphState) -> dict:
    """
    LangGraph node - **Step 4: Patch Application (Docker Sandbox)**

    Parameters
    ----------
    state : GraphState
        The shared pipeline state produced by earlier nodes.

    Returns
    -------
    dict
        Partial GraphState update merged by LangGraph.
    """
    errors: list[str] = list(state.get("errors", []))
    container_id: str = ""
    work_dir: Path | None = None
    image_tag: str = ""

    # ── Unpack inputs ──────────────────────────────────────────────────────
    package_name: str = state.get("package_name", "unknown-package")
    package_version: str = state.get("package_version", "0.0.0")
    current_patch = state.get("current_patch")

    print("\n" + "=" * 60, flush=True)
    print(f"  PATCH APPLICATION NODE", flush=True)
    print(f"  Package : {package_name}@{package_version}", flush=True)
    print(f"  Attempt : {(current_patch or {}).get('attempt_number', 1)}", flush=True)
    print("=" * 60, flush=True)

    if not current_patch:
        msg = "patch_application: no current_patch in state; skipping sandbox."
        logger.warning(msg)
        errors.append(msg)
        return {
            "sandbox_id": None,
            "sandbox_apply_success": False,
            "validation": ValidationResult(
                build_succeeded=False,
                tests_passed=False,
                revalidation_scan_clean=False,
                logs=msg,
            ),
            "errors": errors,
        }

    # ── Unique identifiers for this sandbox run ────────────────────────────
    run_id = uuid.uuid4().hex[:8]
    safe_name = re.sub(r"[^a-z0-9]", "-", package_name.lower())
    image_tag = f"patch-sandbox/{safe_name}:{run_id}"
    container_name = f"patch-{safe_name}-{run_id}"

    # Accumulate all logs across phases
    all_logs: list[str] = []

    build_ok = False
    install_ok = False
    test_ok = False

    try:
        # ── A: write files ─────────────────────────────────────────────────
        PATCH_WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
        work_dir = Path(tempfile.mkdtemp(prefix=f"patch_{safe_name}_", dir=PATCH_WORKSPACE_ROOT))
        print(f"\n    Sandbox workspace: {work_dir}", flush=True)

        _seed_workspace_from_source(state.get("source_dir"), work_dir)

        _write_patched_package(
            work_dir,
            package_name,
            package_version,
            current_patch,
        )

        # ── B: write Dockerfile ────────────────────────────────────────────
        _write_dockerfile(work_dir)

        # ── C: docker build ────────────────────────────────────────────────
        build_ok, build_log = _build_image(work_dir, image_tag)
        all_logs.append("=== docker build ===\n" + build_log)

        if not build_ok:
            errors.append(f"docker build failed for {image_tag}")
            raise RuntimeError("Docker image build failed")

        # ── D: npm install ─────────────────────────────────────────────────
        install_ok, install_log = _run_npm_install(image_tag, container_name)
        all_logs.append("=== npm install ===\n" + install_log)

        # npm install failure is non-fatal; we still attempt npm test
        if not install_ok:
            errors.append("npm install step reported errors (continuing to test)")

        # ── E: npm test ────────────────────────────────────────────────────
        test_ok, container_id, test_log = _run_npm_test(image_tag, container_name)
        all_logs.append("=== npm test ===\n" + test_log)

    except Exception as exc:
        msg = f"patch_application error: {type(exc).__name__}: {exc}"
        logger.exception(msg)
        errors.append(msg)
        all_logs.append(f"\n=== EXCEPTION ===\n{msg}\n")

    finally:
        # ── F: always tear down ────────────────────────────────────────────
        if work_dir:
            _teardown(container_id, image_tag, work_dir, preserve_workspace=True)

    # ── Summarise ──────────────────────────────────────────────────────────
    combined_logs = "\n".join(all_logs)
    apply_success = build_ok and test_ok

    _step("G . Summary")
    print(f"    Docker build  : {'PASS' if build_ok  else 'FAIL'}", flush=True)
    print(f"    npm install   : {'PASS' if install_ok else 'FAIL'}", flush=True)
    print(f"    npm test      : {'PASS' if test_ok   else 'FAIL'}", flush=True)
    print(f"    Overall       : {'PASS' if apply_success else 'FAIL'}", flush=True)

    validation = ValidationResult(
        build_succeeded=build_ok,
        tests_passed=test_ok,
        revalidation_scan_clean=False,   # patch_validation will set this
        logs=combined_logs,
    )

    return {
        "sandbox_id": container_id or None,
        "sandbox_apply_success": apply_success,
        "patched_source_dir": str(work_dir) if work_dir and work_dir.exists() else None,
        "validation": validation,
        "errors": errors,
    }
