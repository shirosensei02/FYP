import io
import tarfile
from pathlib import Path
from subprocess import CompletedProcess

import package_input


def _build_package_tarball(tarball_path: Path) -> None:
    with tarfile.open(tarball_path, "w:gz") as archive:
        package_json = b'{"name":"demo-package","version":"1.0.0"}'
        index_js = b"module.exports = 42;\n"

        package_info = tarfile.TarInfo("package/package.json")
        package_info.size = len(package_json)
        archive.addfile(package_info, io.BytesIO(package_json))

        index_info = tarfile.TarInfo("package/index.js")
        index_info.size = len(index_js)
        archive.addfile(index_info, io.BytesIO(index_js))


def test_package_input_extracts_npm_tarball(monkeypatch, tmp_path):
    packages_root = tmp_path / "packages"
    monkeypatch.setattr(package_input, "PACKAGES_ROOT", packages_root)
    monkeypatch.setattr(package_input.shutil, "which", lambda name: "C:/Program Files/nodejs/npm.cmd")

    def fake_run(command, cwd, capture_output, text, check):
        assert command[1] == "pack"
        tarball_path = Path(command[-1]) / "demo-package-1.0.0.tgz"
        _build_package_tarball(tarball_path)
        return CompletedProcess(command, 0, stdout="demo-package-1.0.0.tgz\n", stderr="")

    monkeypatch.setattr(package_input.subprocess, "run", fake_run)

    result = package_input.package_input({"package_name": "demo-package", "package_version": "1.0.0"})

    assert "errors" not in result
    assert Path(result["source_dir"]).exists()
    assert Path(result["package_manifest_path"]).exists()
    assert Path(result["tarball_path"]).exists()


def test_package_input_reports_missing_package_name():
    result = package_input.package_input({"package_version": "1.0.0"})
    assert result == {"errors": ["package_input: missing package_name"]}
