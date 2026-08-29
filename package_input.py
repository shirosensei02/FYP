from __future__ import annotations

import re
import shutil
import subprocess
import tarfile
from stat import S_IWRITE
from pathlib import Path

from state import GraphState

WORKSPACE_ROOT = Path(__file__).resolve().parent / ".workspace"
PACKAGES_ROOT = WORKSPACE_ROOT / "packages"


def _with_error(state: GraphState, message: str) -> dict:
    errors = list(state.get("errors", []))
    errors.append(message)
    return {"errors": errors}


def _safe_segment(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return sanitized or "unknown"


def _extract_tarball(tarball_path: Path, extract_root: Path) -> Path:
    if extract_root.exists():
        shutil.rmtree(extract_root, onerror=_handle_remove_readonly)

    extract_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball_path, "r:gz") as archive:
        archive.extractall(extract_root)

    package_root = extract_root / "package"
    if package_root.exists():
        return package_root

    package_dirs = [path for path in extract_root.iterdir() if path.is_dir()]
    if len(package_dirs) == 1:
        return package_dirs[0]

    return extract_root


def _handle_remove_readonly(func, path, exc_info) -> None:
    Path(path).chmod(S_IWRITE)
    func(path)


def package_input(state: GraphState) -> dict:
    package_name = state.get("package_name")
    package_version = state.get("package_version")

    if not package_name:
        return _with_error(state, "package_input: missing package_name")

    if not package_version:
        return _with_error(state, "package_input: missing package_version")

    existing_source_dir = state.get("source_dir")
    if existing_source_dir:
        source_dir = Path(existing_source_dir)
        manifest_path = source_dir / "package.json"
        if source_dir.exists() and manifest_path.exists():
            return {
                "source_dir": str(source_dir),
                "package_manifest_path": str(manifest_path),
            }

    target_dir = PACKAGES_ROOT / _safe_segment(package_name) / _safe_segment(package_version)
    target_dir.mkdir(parents=True, exist_ok=True)

    npm_executable = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm_executable:
        return _with_error(state, "package_input: npm is not installed or not on PATH")

    pack_command = [
        npm_executable,
        "pack",
        f"{package_name}@{package_version}",
        "--pack-destination",
        str(target_dir),
    ]
    pack_result = subprocess.run(
        pack_command,
        cwd=target_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if pack_result.returncode != 0:
        stderr = pack_result.stderr.strip() or pack_result.stdout.strip()
        return _with_error(state, f"package_input: npm pack failed: {stderr}")

    stdout_lines = [line.strip() for line in pack_result.stdout.splitlines() if line.strip()]
    tarball_name = stdout_lines[-1] if stdout_lines else ""
    tarball_path = target_dir / tarball_name
    if not tarball_name or not tarball_path.exists():
        tarballs = sorted(target_dir.glob("*.tgz"), key=lambda path: path.stat().st_mtime, reverse=True)
        if not tarballs:
            return _with_error(state, "package_input: npm pack succeeded but no tarball was found")
        tarball_path = tarballs[0]

    extract_root = target_dir / "source"
    package_root = _extract_tarball(tarball_path, extract_root)
    manifest_path = package_root / "package.json"
    if not manifest_path.exists():
        return _with_error(
            state,
            f"package_input: extracted package does not contain package.json at {manifest_path}",
        )

    return {
        "package_name": package_name,
        "package_version": package_version,
        "source_dir": str(package_root),
        "package_manifest_path": str(manifest_path),
        "tarball_path": str(tarball_path),
    }
