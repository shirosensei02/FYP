import json
from pathlib import Path

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
        return _FakeResponse(
            json.dumps(
                {
                    "diff": "--- a/index.js\n+++ b/index.js\n@@\n-module.exports = 42;\n+module.exports = 43;\n",
                    "rationale": "Demonstrates a structured patch payload.",
                    "target_files": ["index.js"],
                }
            )
        )


def test_patch_generation_returns_structured_patch(monkeypatch, tmp_path):
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


def test_patch_generation_requires_api_key(tmp_path, monkeypatch):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","version":"1.0.0"}', encoding="utf-8")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    result = patch_generation.patch_generation(
        {
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "vulnerabilities": [{"id": "CVE-TEST-0001"}],
        }
    )

    assert result["errors"] == ["patch_generation: OPENAI_API_KEY is not set"]
