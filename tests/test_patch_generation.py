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
                    "diff": "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-module.exports = 42;\n+module.exports = 43;\n",
                    "rationale": "Demonstrates a structured patch payload.",
                    "target_files": ["index.js"],
                }
            )
        )


class _FakeGeminiResponse:
    text = json.dumps(
        {
            "diff": "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-module.exports = 42;\n+module.exports = 43;\n",
            "target_files": ["index.js"],
        }
    )


class _FakeGeminiClient:
    def __init__(self, api_key: str):
        assert api_key == "test-key"
        self.models = self

    def generate_content(self, model, contents, config):
        assert model == "gemini-3.6-flash"
        assert config["response_mime_type"] == "application/json"
        payload = json.loads(contents)
        assert payload["vulnerabilities"][0]["id"] == "CVE-TEST-0001"
        return _FakeGeminiResponse()


class _FakeGeminiModule:
    Client = _FakeGeminiClient


class _FakeOpenRouterResponse:
    choices = [
        type(
            "Choice",
            (),
            {
                "message": type(
                    "Message",
                    (),
                    {
                        "content": (
                            "Root cause identified.\n\n"
                            "```diff\n"
                            "--- a/index.js\n"
                            "+++ b/index.js\n"
                            "@@ -1 +1 @@\n"
                            "-module.exports = 42;\n"
                            "+module.exports = 43;\n"
                            "```"
                        )
                    },
                )()
            },
        )()
    ]


class _FakeOpenRouterCompletions:
    def create(self, model, temperature, max_tokens, response_format, extra_body, messages):
        assert model == "qwen/qwen3-coder:free", model
        assert temperature == 0, temperature
        assert max_tokens == patch_generation.OPENROUTER_MAX_TOKENS, max_tokens
        assert response_format == {"type": "json_object"}, response_format
        assert extra_body == {"reasoning": {"enabled": False, "exclude": True}}, extra_body
        assert messages[0]["role"] == "system", messages
        assert messages[1]["role"] == "user", messages
        assert "CVE-TEST-0001" in messages[1]["content"], messages[1]["content"]
        return _FakeOpenRouterResponse()


class _FakeOpenRouter:
    def __init__(self, api_key, base_url, timeout):
        assert api_key == "test-key"
        assert base_url == "https://openrouter.example/api/v1"
        assert timeout == 180.0
        self.chat = type(
            "Chat",
            (),
            {"completions": _FakeOpenRouterCompletions()},
        )()


class _InvalidOpenRouterCompletions:
    def __init__(self):
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        return _FakeResponse('{"summary": "The package is vulnerable to ReDoS."}')


class _InvalidOpenRouter:
    def __init__(self, **kwargs):
        self.completions = _InvalidOpenRouterCompletions()
        self.chat = type("Chat", (), {"completions": self.completions})()


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
    assert result["patch_attempts"][0]["attempt_id"].startswith("demo-package-")
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

    assert result["current_patch"]["attempt_id"].startswith("demo-package-")
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
    assert result["current_patch"]["attempt_id"].startswith("package-")


def test_context_includes_non_entrypoint_implementation_files(tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","main":"index.js"}', encoding="utf-8")
    (source_dir / "index.js").write_text("module.exports = require('./functions/parse')\n", encoding="utf-8")
    functions_dir = source_dir / "functions"
    functions_dir.mkdir()
    (functions_dir / "parse.js").write_text("module.exports = () => 'implementation'\n", encoding="utf-8")

    context_paths = {item["path"] for item in patch_generation._read_context_files(source_dir, manifest_path)}

    assert "functions/parse.js" in context_paths


def test_context_follows_entrypoint_local_imports(tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","main":"index.js"}', encoding="utf-8")
    (source_dir / "index.js").write_text("module.exports = require('./lib/entry')\n", encoding="utf-8")
    lib_dir = source_dir / "lib"
    lib_dir.mkdir()
    (lib_dir / "entry.js").write_text("module.exports = require('../internal/fix')\n", encoding="utf-8")
    internal_dir = source_dir / "internal"
    internal_dir.mkdir()
    (internal_dir / "fix.js").write_text("module.exports = () => 'patched'\n", encoding="utf-8")

    context_paths = {item["path"] for item in patch_generation._read_context_files(source_dir, manifest_path)}

    assert {"index.js", "lib/entry.js", "internal/fix.js"} <= context_paths


def test_patch_generation_gemini_provider_uses_configured_model(monkeypatch, tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","version":"1.0.0","main":"index.js"}', encoding="utf-8")
    (source_dir / "index.js").write_text("module.exports = 42;\n", encoding="utf-8")

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(patch_generation, "genai", _FakeGeminiModule)

    result = patch_generation.patch_generation(
        {
            "package_name": "demo-package",
            "package_version": "1.0.0",
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "model_provider": "gemini",
            "vulnerabilities": [{"id": "CVE-TEST-0001"}],
        }
    )

    assert result["current_patch"]["model_used"] == "gemini-3.6-flash"
    assert result["current_patch"]["target_files"] == ["index.js"]


def test_patch_generation_gemini_provider_requires_api_key(monkeypatch, tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","version":"1.0.0"}', encoding="utf-8")

    monkeypatch.setattr(patch_generation, "genai", _FakeGeminiModule)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    result = patch_generation.patch_generation(
        {
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "model_provider": "gemini",
            "vulnerabilities": [{"id": "CVE-TEST-0001"}],
        }
    )

    assert result["errors"] == ["patch_generation: GEMINI_API_KEY is not set"]


def test_patch_generation_openrouter_provider_uses_configured_model(monkeypatch, tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","version":"1.0.0","main":"index.js"}', encoding="utf-8")
    (source_dir / "index.js").write_text("module.exports = 42;\n", encoding="utf-8")

    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setenv("OPENROUTER_BASE_URL", "https://openrouter.example/api/v1")
    monkeypatch.setattr(patch_generation, "OpenAI", _FakeOpenRouter)

    result = patch_generation.patch_generation(
        {
            "package_name": "demo-package",
            "package_version": "1.0.0",
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "model_provider": "openrouter",
            "model_name": "qwen/qwen3-coder:free",
            "vulnerabilities": [{"id": "CVE-TEST-0001", "description": "Test vulnerability"}],
        }
    )

    assert result["current_patch"]["model_used"] == "qwen/qwen3-coder:free"
    assert "--- a/index.js" in result["current_patch"]["diff"]


def test_openrouter_explanation_only_response_is_repaired_once_then_recorded_as_failure(monkeypatch, tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","version":"1.0.0"}', encoding="utf-8")

    client = _InvalidOpenRouter()
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr(patch_generation, "OpenAI", lambda **kwargs: client)

    result = patch_generation.patch_generation(
        {
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "model_provider": "openrouter",
            "model_name": "nvidia/nemotron-3-super-120b-a12b:free",
            "vulnerabilities": [{"id": "CVE-TEST-0001"}],
        }
    )

    assert client.completions.calls == 2
    assert result["generation_status"] == "failed"
    assert result["generation_model_used"] == "nvidia/nemotron-3-super-120b-a12b:free"
    assert result["current_patch"] is None
    assert "invalid or incomplete patch response" in result["generation_error"]


def test_unified_diff_validation_rejects_placeholder_hunk_and_trailing_explanation():
    assert not patch_generation._is_complete_unified_diff(
        "--- a/index.js\n+++ b/index.js\n@@ -... @@\n-old\n+new\n"
    )
    assert not patch_generation._is_complete_unified_diff(
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-old\n+new\nThis fixes the issue."
    )


def test_unified_diff_validation_accepts_multiple_complete_files():
    diff = (
        "diff --git a/a.js b/a.js\n"
        "--- a/a.js\n+++ b/a.js\n@@ -1 +1 @@\n-old\n+new\n"
        "diff --git a/b.js b/b.js\n"
        "--- a/b.js\n+++ b/b.js\n@@ -1 +1 @@\n-before\n+after\n"
    )
    assert patch_generation._is_complete_unified_diff(diff)


def test_patch_generation_repairs_an_invalid_model_response(monkeypatch, tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","main":"index.js"}', encoding="utf-8")
    (source_dir / "index.js").write_text("module.exports = 42;\n", encoding="utf-8")

    calls: list[str | None] = []

    def fake_generator(state, vulnerabilities, context_files, repair_feedback=None):
        calls.append(repair_feedback)
        if repair_feedback is None:
            return "patch_generation: model returned an invalid patch response"
        assert "`edits` list" in repair_feedback
        assert "Do not modify package.json version metadata" in repair_feedback
        return {
            "edits": [{
                "path": "index.js",
                "old_text": "module.exports = 42;\n",
                "new_text": "module.exports = 43;\n",
            }]
        }

    monkeypatch.setattr(patch_generation, "_generate_with_openai", fake_generator)

    result = patch_generation.patch_generation(
        {
            "package_name": "demo-package",
            "package_version": "1.0.0",
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "model_provider": "openai",
            "vulnerabilities": [{"id": "CVE-TEST-0001"}],
        }
    )

    assert calls[0] is None
    assert len(calls) == 2
    assert result["generation_status"] == "generated"


def test_diff_preflight_rejects_context_that_does_not_match_source(tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    (source_dir / "index.js").write_text("module.exports = 42;\n", encoding="utf-8")

    error = patch_generation._validate_diff_against_source(
        source_dir,
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-module.exports = 41;\n+module.exports = 43;\n",
    )

    assert error is not None
    assert "patch does not apply" in error


def test_structured_edit_requires_exactly_one_source_match(tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    (source_dir / "index.js").write_text("const value = 1;\nconst value = 1;\n", encoding="utf-8")

    result = patch_generation._materialize_structured_edits(
        source_dir,
        {
            "edits": [{
                "path": "index.js",
                "old_text": "const value = 1;\n",
                "new_text": "const value = 2;\n",
            }]
        },
    )

    assert isinstance(result, str)
    assert "exactly once" in result


def test_patch_generation_repairs_a_diff_that_fails_preflight(monkeypatch, tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","main":"index.js"}', encoding="utf-8")
    (source_dir / "index.js").write_text("module.exports = 42;\n", encoding="utf-8")

    calls: list[str | None] = []

    def fake_generator(state, vulnerabilities, context_files, repair_feedback=None):
        calls.append(repair_feedback)
        if repair_feedback is None:
            return {"diff": "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-module.exports = 41;\n+module.exports = 43;\n"}
        assert "patch does not apply" in repair_feedback
        return {"diff": "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-module.exports = 42;\n+module.exports = 43;\n"}

    monkeypatch.setattr(patch_generation, "_generate_with_openai", fake_generator)

    result = patch_generation.patch_generation(
        {
            "package_name": "demo-package",
            "package_version": "1.0.0",
            "source_dir": str(source_dir),
            "package_manifest_path": str(manifest_path),
            "model_provider": "openai",
            "vulnerabilities": [{"id": "CVE-TEST-0001"}],
        }
    )

    assert calls[0] is None
    assert len(calls) == 2
    assert result["generation_status"] == "generated"
    assert "+module.exports = 43;" in result["current_patch"]["diff"]


def test_context_excerpt_keeps_late_scanner_matched_source(tmp_path):
    source_dir = tmp_path / "package"
    source_dir.mkdir()
    manifest_path = source_dir / "package.json"
    manifest_path.write_text('{"name":"demo-package","main":"index.js"}', encoding="utf-8")
    (source_dir / "index.js").write_text(
        "// beginning\n" + ("const before = true;\n" * 400) + "function vulnerableParser(value) { return value }\n" + ("const after = true;\n" * 400),
        encoding="utf-8",
    )

    context = patch_generation._read_context_files(
        source_dir,
        manifest_path,
        {"vulnerableparser"},
    )
    index_excerpt = next(item["content"] for item in context if item["path"] == "index.js")

    assert "function vulnerableParser" in index_excerpt
    assert "omitted unrelated source" in index_excerpt


def test_openrouter_prompt_requires_a_reachable_behavioral_security_fix():
    prompt = patch_generation._build_openrouter_prompt(
        {"package_name": "demo", "package_version": "1.0.0"},
        [{"id": "CVE-TEST-0001", "description": "unsafe parser"}],
        [{"path": "index.js", "content": "function parse(value) { return value; }\n"}],
    )

    assert "must change reachable runtime behavior on the vulnerable path" in prompt
    assert "Do not add unused variables" in prompt
    assert "silently verify" in prompt


def test_source_excerpt_prioritizes_a_relevant_function_over_earlier_mentions():
    contents = (
        "const templateSettings = {};\n"
        + ("const unrelated = true;\n" * 3_000)
        + "function template(value, options) {\n"
        + "  const imports = options.imports;\n"
        + "  return imports[value];\n"
        + "}\n"
        + ("const trailing = true;\n" * 500)
    )

    excerpt = patch_generation._source_excerpt(contents, {"template", "imports"})

    assert "function template(value, options)" in excerpt
    assert "const imports = options.imports;" in excerpt
