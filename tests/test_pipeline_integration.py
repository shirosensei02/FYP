import io
import json
import tarfile
from pathlib import Path
from subprocess import CompletedProcess

from package_input import package_input
from patch_generation import patch_generation
from vulnerability_detection import vulnerability_detection


def _build_package_tarball(tarball_path: Path) -> None:
    with tarfile.open(tarball_path, "w:gz") as archive:
        package_json = b'{"name":"demo-package","version":"1.0.0","main":"index.js"}'
        index_js = b"module.exports = 42;\n"

        package_info = tarfile.TarInfo("package/package.json")
        package_info.size = len(package_json)
        archive.addfile(package_info, io.BytesIO(package_json))

        index_info = tarfile.TarInfo("package/index.js")
        index_info.size = len(index_js)
        archive.addfile(index_info, io.BytesIO(index_js))


def test_pipeline_integration_with_mocked_external_tools(monkeypatch, tmp_path):
    import package_input as package_input_module
    import vulnerability_detection as vulnerability_detection_module

    packages_root = tmp_path / "packages"
    scans_root = tmp_path / "scans"

    monkeypatch.setattr(package_input_module, "PACKAGES_ROOT", packages_root)
    monkeypatch.setattr(vulnerability_detection_module, "SCANS_ROOT", scans_root)
    monkeypatch.setattr(
        package_input_module.shutil,
        "which",
        lambda name: "C:/Program Files/nodejs/npm.cmd" if name in {"npm.cmd", "npm"} else None,
    )

    def fake_package_run(command, cwd, capture_output, text, check):
        tarball_path = Path(command[-1]) / "demo-package-1.0.0.tgz"
        _build_package_tarball(tarball_path)
        return CompletedProcess(command, 0, stdout="demo-package-1.0.0.tgz\n", stderr="")

    monkeypatch.setattr(package_input_module.subprocess, "run", fake_package_run)

    state = {
        "package_name": "demo-package",
        "package_version": "1.0.0",
        "model_provider": "mock",
    }
    state.update(package_input(state))

    def fake_tool_which(name):
        return f"C:/tools/{name}.exe"

    tool_outputs = [
        CompletedProcess(
            ["syft"],
            0,
            stdout=json.dumps({"artifacts": [{"name": "demo-package", "version": "1.0.0"}]}),
            stderr="",
        ),
        CompletedProcess(
            ["grype"],
            0,
            stdout=json.dumps(
                {
                    "matches": [
                        {
                            "artifact": {"name": "demo-package", "version": "1.0.0"},
                            "vulnerability": {
                                "id": "CVE-TEST-PIPELINE",
                                "severity": "High",
                                "description": "Pipeline test vulnerability",
                                "fix": {"versions": ["1.0.1"]},
                                "advisories": [{"id": "GHSA-pipeline"}],
                            },
                        }
                    ]
                }
            ),
            stderr="",
        ),
    ]

    def fake_detection_run(*args, **kwargs):
        return tool_outputs.pop(0)

    monkeypatch.setattr(vulnerability_detection_module.shutil, "which", fake_tool_which)
    monkeypatch.setattr(vulnerability_detection_module.subprocess, "run", fake_detection_run)

    state.update(vulnerability_detection(state))
    state.update(patch_generation(state))

    assert state["source_dir"]
    assert state["vulnerabilities"][0]["id"] == "CVE-TEST-PIPELINE"
    assert state["current_vulnerabilities"][0]["id"] == "CVE-TEST-PIPELINE"
    assert state["current_patch"]["attempt_id"] == "attempt-1-CVE-TEST-PIPELINE"
    assert state["current_patch"]["target_files"] == ["index.js"]
    assert "MOCK PATCH" in state["current_patch"]["diff"]
