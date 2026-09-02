import json

import patch_generation


class _FakeResponse:
    def __init__(self, content: str):
        self.choices = [type("Choice", (), {"message": type("Message", (), {"content": content})()})()]


class _FakeOpenAI:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.chat = type("Chat", (), {"completions": self})()

    def create(self, model, response_format, messages):
        assert model == "gpt-4.1-mini"
        assert response_format == {"type": "json_object"}
        assert messages[0]["role"] == "system"
        payload = json.loads(messages[1]["content"])
        assert len(payload["vulnerabilities"]) == 2
        return _FakeResponse(
            json.dumps(
                {
                    "diff": "--- a/index.js\n+++ b/index.js\n@@\n-module.exports = 42;\n+module.exports = 43;\n",
                    "rationale": "Demonstrates a structured patch payload.",
                    "target_files": ["index.js"],
                }
            )
        )


def test_patch_generation_mock_provider_returns_deterministic_diff(tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","version":"1.0.0","main":"index.js"}', encoding="utf-8")
    (source_dir / "index.js").write_text("module.exports = 42;\n", encoding="utf-8")

    result = patch_generation.patch_generation(
        {
            "package_name": "demo-package",
            "package_version": "1.0.0",
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "model_provider": "mock",
            "vulnerabilities": [
                {
                    "id": "CVE-TEST-0001",
                    "severity": "high",
                    "package": "demo-package",
                    "installed_version": "1.0.0",
                    "fixed_version": "1.0.1",
                    "description": "Test vulnerability",
                }
            ],
        }
    )

    assert result["current_patch"]["vulnerability_id"] == "CVE-TEST-0001"
    assert result["current_patch"]["target_files"] == ["index.js"]
    assert result["patch_attempts"][0]["attempt_number"] == 1
    assert result["patch_attempts"][0]["attempt_id"] == "attempt-1-CVE-TEST-0001"
    assert "--- a/index.js" in result["current_patch"]["diff"]
    assert "MOCK PATCH" in result["current_patch"]["diff"]


def test_patch_generation_openai_provider_uses_full_vulnerability_list(monkeypatch, tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","version":"1.0.0","main":"index.js"}', encoding="utf-8")
    (source_dir / "index.js").write_text("module.exports = 42;\n", encoding="utf-8")

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(patch_generation, "OpenAI", _FakeOpenAI)

    result = patch_generation.patch_generation(
        {
            "package_name": "demo-package",
            "package_version": "1.0.0",
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "model_provider": "openai",
            "model_name": "gpt-4.1-mini",
            "patch_scope": "all",
            "vulnerabilities": [
                {"id": "CVE-TEST-0001", "description": "Test vulnerability 1"},
                {"id": "CVE-TEST-0002", "description": "Test vulnerability 2"},
            ],
        }
    )

    assert result["current_patch"]["attempt_id"] == "attempt-1-multi-2"
    assert result["current_patch"]["model_used"] == "gpt-4.1-mini"


def test_patch_generation_openai_provider_requires_api_key(tmp_path, monkeypatch):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","version":"1.0.0"}', encoding="utf-8")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    result = patch_generation.patch_generation(
        {
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "model_provider": "openai",
            "vulnerabilities": [{"id": "CVE-TEST-0001"}],
        }
    )

    assert result["errors"] == ["patch_generation: OPENAI_API_KEY is not set"]


def test_patch_generation_prefers_current_vulnerabilities_for_single_scope(tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","version":"1.0.0","main":"index.js"}', encoding="utf-8")
    (source_dir / "index.js").write_text("module.exports = 42;\n", encoding="utf-8")

    result = patch_generation.patch_generation(
        {
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "model_provider": "mock",
            "patch_scope": "single",
            "vulnerabilities": [{"id": "CVE-OLD-0001"}],
            "current_vulnerabilities": [{"id": "CVE-CURRENT-0001"}],
        }
    )

    assert result["current_patch"]["vulnerability_id"] == "CVE-CURRENT-0001"
    assert result["current_patch"]["attempt_id"] == "attempt-1-CVE-CURRENT-0001"
