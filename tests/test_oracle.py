import subprocess
from pathlib import Path
from types import SimpleNamespace

import oracle_generation as generation
import oracle_validation as validation


SAFE_SOURCE = """
const fs = require('node:fs');
console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: true,
  exploit_succeeded: fs.existsSync('/tmp/oracle-marker'),
  evidence: 'checked marker'
}));
"""


def _execution(status, operation=True, exploit=False):
    return {
        "status": status,
        "operation_completed": operation,
        "exploit_succeeded": exploit,
        "evidence": status,
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
    }


def test_oracle_parser_accepts_protocol_and_rejects_process_launching():
    parsed = generation._parse_candidate(
        '{"source": ' + __import__('json').dumps(SAFE_SOURCE) + ', "explanation": "test"}',
        1,
        "model",
    )
    assert not isinstance(parsed, str)
    assert parsed["status"] == "generated"

    unsafe = SAFE_SOURCE + "\nrequire('node:child_process').exec('id');"
    rejected = generation._parse_candidate(
        '{"source": ' + __import__('json').dumps(unsafe) + '}', 1, "model"
    )
    assert "forbidden capability" in rejected


def test_oracle_parser_allows_normal_javascript_function_syntax():
    source = SAFE_SOURCE + "\n;[1].forEach(function (value) { return value; });"
    parsed = generation._parse_candidate(
        '{"source": ' + __import__('json').dumps(source) + '}', 1, "model"
    )
    assert not isinstance(parsed, str)


def test_oracle_parser_accepts_only_trusted_fixture_names():
    payload = __import__('json').dumps({
        "source": SAFE_SOURCE,
        "requirements": ["requires_git_repository"],
    })
    parsed = generation._parse_candidate(payload, 1, "model")
    assert parsed["requirements"] == ["requires_git_repository"]

    rejected = generation._parse_candidate(__import__('json').dumps({
        "source": SAFE_SOURCE,
        "requirements": ["run_arbitrary_setup"],
    }), 1, "model")
    assert "unsupported trusted fixture" in rejected


def test_git_fixture_installs_git_and_initializes_writable_repository():
    dockerfile, entrypoint = validation._oracle_environment({
        "requirements": ["requires_git_repository"],
    })
    assert "apt-get install -y --no-install-recommends git" in dockerfile
    assert "COPY oracle.js /consumer/oracle.js" in dockerfile
    assert "git init -q" in entrypoint
    assert "git commit" in entrypoint
    assert "repository=/tmp/oracle-repository" in entrypoint
    assert "npm init" not in entrypoint
    assert "oracle-fixture" in entrypoint
    assert "exec node /consumer/oracle.js" in entrypoint


def test_writable_tmp_fixture_selects_a_writable_working_directory():
    _, entrypoint = validation._oracle_environment({
        "requirements": ["requires_writable_tmp"],
    })
    assert "mkdir -p /tmp/oracle-workspace" in entrypoint
    assert "cd /tmp/oracle-workspace" in entrypoint


def test_oracle_generation_skips_without_a_fixed_baseline(tmp_path):
    result = generation.oracle_generation({
        "model_provider": "openrouter",
        "source_dir": str(tmp_path),
        "answer_key": {"status": "unavailable"},
    })
    assert result["oracle_candidate"]["status"] == "skipped"
    assert result["oracle_attempt_count"] == 1


def test_oracle_generation_treats_none_content_as_invalid(monkeypatch, tmp_path):
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=None))]
    )
    completions = SimpleNamespace(create=lambda **kwargs: response)
    fake_client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr(generation, "OpenAI", lambda **kwargs: fake_client)
    monkeypatch.setattr(generation, "record_request", lambda *args, **kwargs: None)
    monkeypatch.setattr(generation, "response_cost", lambda value: 0.0)
    result = generation.oracle_generation({
        "model_provider": "openrouter",
        "source_dir": str(tmp_path),
        "answer_key": {"diff": "patch"},
    })
    assert result["oracle_candidate"]["status"] == "invalid"


def test_baseline_validation_accepts_only_exploitable_then_blocked(monkeypatch, tmp_path):
    vulnerable = tmp_path / "vulnerable"
    fixed = tmp_path / "fixed"
    vulnerable.mkdir()
    fixed.mkdir()
    candidate = {
        "status": "generated", "attempt_number": 1, "source": SAFE_SOURCE,
        "timeout_seconds": 30, "language": "javascript",
    }
    monkeypatch.setattr(validation, "_prepare_fixed_workspace", lambda state, parent: (fixed, None))
    results = iter([
        _execution("EXPLOIT_SUCCEEDED", exploit=True),
        _execution("EXPLOIT_BLOCKED", exploit=False),
    ])
    monkeypatch.setattr(validation, "_run_oracle", lambda *args: next(results))

    result = validation.oracle_validation({
        "source_dir": str(vulnerable),
        "oracle_candidate": candidate,
        "oracle_attempts": [{"attempt_number": 1, "generation": candidate}],
    })
    assert result["oracle_validation"]["status"] == "VALID"
    assert result["accepted_oracle"]["status"] == "accepted"
    assert result["oracle_attempts"][-1]["validation"]["status"] == "VALID"


def test_baseline_validation_returns_structured_feedback(monkeypatch, tmp_path):
    vulnerable = tmp_path / "vulnerable"
    fixed = tmp_path / "fixed"
    vulnerable.mkdir()
    fixed.mkdir()
    candidate = {"status": "generated", "attempt_number": 1, "source": SAFE_SOURCE}
    monkeypatch.setattr(validation, "_prepare_fixed_workspace", lambda state, parent: (fixed, None))
    monkeypatch.setattr(
        validation, "_run_oracle", lambda *args: _execution("EXPLOIT_BLOCKED", exploit=False)
    )
    result = validation.oracle_validation({
        "source_dir": str(vulnerable), "oracle_candidate": candidate,
        "oracle_attempts": [{"attempt_number": 1}],
    })
    assert result["oracle_validation"]["status"] == "INVALID"
    assert result["oracle_feedback"]["vulnerable"]["status"] == "EXPLOIT_BLOCKED"


def test_baseline_feedback_identifies_git_prerequisite_failure(monkeypatch, tmp_path):
    vulnerable = tmp_path / "vulnerable"
    fixed = tmp_path / "fixed"
    vulnerable.mkdir()
    fixed.mkdir()
    candidate = {"status": "generated", "attempt_number": 1, "source": SAFE_SOURCE}
    monkeypatch.setattr(validation, "_prepare_fixed_workspace", lambda state, parent: (fixed, None))
    monkeypatch.setattr(validation, "_run_oracle", lambda *args: {
        **_execution("OPERATION_FAILED", operation=False, exploit=False),
        "stderr": "fatal: not a git repository",
    })
    result = validation.oracle_validation({
        "source_dir": str(vulnerable), "oracle_candidate": candidate,
        "oracle_attempts": [{"attempt_number": 1}],
    })
    assert any("requires_git_repository" in hint for hint in result["oracle_feedback"]["guidance"])


def test_invalid_candidate_feedback_includes_previous_source():
    rejected_source = SAFE_SOURCE + "\nrequire('node:child_process');"
    result = validation.oracle_validation({
        "oracle_candidate": {
            "status": "invalid",
            "source": rejected_source,
            "explanation": "forbidden capability",
        },
        "oracle_attempts": [{"attempt_number": 1}],
    })
    assert result["oracle_validation"]["status"] == "INVALID"
    prompt = generation._prompt({
        "oracle_feedback": result["oracle_feedback"],
        "oracle_candidate": {"source": rejected_source},
    })
    payload = __import__('json').loads(prompt.split("INPUT:\n", 1)[1])
    assert payload["previous_failure"]["previous_oracle_source"] == rejected_source


def test_generated_patch_oracle_distinguishes_security_and_regression(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation, "_run_oracle", lambda *args: _execution("EXPLOIT_BLOCKED", exploit=False)
    )
    state = {
        "accepted_oracle": {"source": SAFE_SOURCE},
        "patched_source_dir": str(tmp_path),
        "patch_applied": True,
    }
    result = validation.generated_patch_oracle_validation(state)
    assert result["generated_patch_oracle_validation"]["status"] == "SECURITY_PASS"

    monkeypatch.setattr(
        validation, "_run_oracle", lambda *args: _execution("OPERATION_FAILED", operation=False, exploit=False)
    )
    result = validation.generated_patch_oracle_validation(state)
    assert result["generated_patch_oracle_validation"]["status"] == "REGRESSION"


def test_generated_patch_oracle_skips_when_patch_did_not_apply(monkeypatch, tmp_path):
    monkeypatch.setattr(
        validation,
        "_run_oracle",
        lambda *args: (_ for _ in ()).throw(AssertionError("oracle should not run")),
    )
    result = validation.generated_patch_oracle_validation({
        "accepted_oracle": {"source": SAFE_SOURCE},
        "patched_source_dir": str(tmp_path),
        "patch_applied": False,
    })
    assert result["generated_patch_oracle_validation"]["status"] == "SKIPPED"


def test_baseline_infrastructure_failure_is_error_not_invalid(monkeypatch, tmp_path):
    vulnerable = tmp_path / "vulnerable"
    fixed = tmp_path / "fixed"
    vulnerable.mkdir()
    fixed.mkdir()
    candidate = {"status": "generated", "attempt_number": 1, "source": SAFE_SOURCE}
    monkeypatch.setattr(validation, "_prepare_fixed_workspace", lambda state, parent: (fixed, None))
    results = iter([_execution("INFRA_ERROR", operation=False, exploit=None)])
    monkeypatch.setattr(validation, "_run_oracle", lambda *args: next(results))
    result = validation.oracle_validation({
        "source_dir": str(vulnerable),
        "oracle_candidate": candidate,
        "oracle_attempts": [{"attempt_number": 1}],
    })
    assert result["oracle_validation"]["status"] == "ERROR"
    assert result["oracle_validation"]["fixed"] is None


def test_runner_uses_restricted_runtime_and_parses_result(monkeypatch, tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    (package / "package.json").write_text('{"name":"demo","version":"1.0.0"}')
    monkeypatch.setattr(validation, "ORACLE_WORKSPACE_ROOT", tmp_path / "oracle-work")
    validation.ORACLE_WORKSPACE_ROOT.mkdir()
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[:2] == ["docker", "run"]:
            stdout = 'ORACLE_RESULT {"operation_completed":true,"exploit_succeeded":false,"evidence":"blocked"}\n'
            return subprocess.CompletedProcess(command, 0, stdout, "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(validation.subprocess, "run", fake_run)
    result = validation._run_oracle(package, {"source": SAFE_SOURCE, "timeout_seconds": 10}, "fixed")
    run_command = next(command for command in commands if command[:2] == ["docker", "run"])
    assert result["status"] == "EXPLOIT_BLOCKED"
    assert "--network" in run_command and "none" in run_command
    assert "--read-only" in run_command
    assert "--cap-drop" in run_command and "ALL" in run_command
    assert "--pids-limit" in run_command


def test_runner_can_retain_diagnostic_artifacts(monkeypatch, tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    (package / "package.json").write_text('{"name":"demo","version":"1.0.0"}')
    workspace = tmp_path / "oracle-work"
    workspace.mkdir()
    monkeypatch.setattr(validation, "ORACLE_WORKSPACE_ROOT", workspace)
    monkeypatch.setenv("ORACLE_KEEP_FAILED", "true")

    def fake_run(command, **kwargs):
        if command[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(command, 1, "", "git: not found")
        return subprocess.CompletedProcess(command, 0, "build output", "")

    monkeypatch.setattr(validation.subprocess, "run", fake_run)
    validation._run_oracle(package, {
        "source": SAFE_SOURCE, "attempt_number": 3,
        "requirements": ["requires_git_repository"],
    }, "vulnerable")
    retained = next(workspace.iterdir())
    assert (retained / "oracle.js").is_file()
    assert (retained / "Dockerfile").is_file()
    assert (retained / "runtime.stderr.txt").read_text() == "git: not found"
    assert __import__('json').loads((retained / "attempt.json").read_text())["attempt_number"] == 3


def test_runner_does_not_retain_successful_execution(monkeypatch, tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    (package / "package.json").write_text('{"name":"demo","version":"1.0.0"}')
    workspace = tmp_path / "oracle-work"
    workspace.mkdir()
    monkeypatch.setattr(validation, "ORACLE_WORKSPACE_ROOT", workspace)
    monkeypatch.setenv("ORACLE_KEEP_FAILED", "true")

    def fake_run(command, **kwargs):
        if command[:2] == ["docker", "run"]:
            stdout = 'ORACLE_RESULT {"operation_completed":true,"exploit_succeeded":false,"evidence":"blocked"}\n'
            return subprocess.CompletedProcess(command, 0, stdout, "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(validation.subprocess, "run", fake_run)
    result = validation._run_oracle(package, {"source": SAFE_SOURCE}, "fixed")
    assert result["status"] == "EXPLOIT_BLOCKED"
    assert list(workspace.iterdir()) == []


def test_git_missing_hint_requires_git_specific_enoent():
    unrelated = _execution("OPERATION_FAILED", operation=False, exploit=False)
    unrelated["stderr"] = "ENOENT: missing fixture.txt while checking git metadata"
    assert not any("Git executable missing" in hint for hint in validation._failure_guidance(unrelated))

    missing_git = dict(unrelated)
    missing_git["stderr"] = "Error: spawn git ENOENT"
    assert any("Git executable missing" in hint for hint in validation._failure_guidance(missing_git))


def test_runner_honors_valid_result_even_with_nonzero_exit(monkeypatch, tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    (package / "package.json").write_text('{"name":"demo","version":"1.0.0"}')
    monkeypatch.setattr(validation, "ORACLE_WORKSPACE_ROOT", tmp_path / "oracle-work")
    validation.ORACLE_WORKSPACE_ROOT.mkdir()

    def fake_run(command, **kwargs):
        if command[:2] == ["docker", "run"]:
            stdout = 'ORACLE_RESULT {"operation_completed":true,"exploit_succeeded":true,"evidence":"hit"}\n'
            return subprocess.CompletedProcess(command, 1, stdout, "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(validation.subprocess, "run", fake_run)
    result = validation._run_oracle(package, {"source": SAFE_SOURCE}, "vulnerable")
    assert result["status"] == "EXPLOIT_SUCCEEDED"
    assert result["exit_code"] == 1


def test_runner_classifies_docker_run_exit_125_as_infrastructure(monkeypatch, tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    (package / "package.json").write_text('{"name":"demo","version":"1.0.0"}')
    monkeypatch.setattr(validation, "ORACLE_WORKSPACE_ROOT", tmp_path / "oracle-work")
    validation.ORACLE_WORKSPACE_ROOT.mkdir()

    def fake_run(command, **kwargs):
        if command[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(command, 125, "", "daemon unavailable")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(validation.subprocess, "run", fake_run)
    result = validation._run_oracle(package, {"source": SAFE_SOURCE}, "vulnerable")
    assert result["status"] == "INFRA_ERROR"
    assert result["failure_kind"] == "infrastructure"


def test_prepare_fixed_workspace_prefers_published_package(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    extracted = tmp_path / "published-fixed"
    commands = []
    monkeypatch.setattr(validation.shutil, "which", lambda name: "npm.cmd" if name == "npm.cmd" else None)

    def fake_run(command, **kwargs):
        commands.append(command)
        packed = Path(command[command.index("--pack-destination") + 1])
        (packed / "demo-2.0.0.tgz").write_bytes(b"archive")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(validation.subprocess, "run", fake_run)
    monkeypatch.setattr(validation, "_safe_extract", lambda archive, destination: extracted)
    fixed, error = validation._prepare_fixed_workspace({
        "source_dir": str(source),
        "package_name": "demo",
        "answer_key": {"first_patched_version": "2.0.0", "diff": "unused diff"},
    }, tmp_path / "work")
    assert fixed == extracted
    assert error is None
    assert commands[0][0] == "npm.cmd"


def test_prepare_fixed_workspace_falls_back_to_diff(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "package.json").write_text('{"name":"demo","version":"1.0.0"}')
    monkeypatch.setattr(validation.shutil, "which", lambda name: "npm.cmd" if name == "npm.cmd" else None)
    monkeypatch.setattr(
        validation.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "", "not found"),
    )
    applied = []

    def fake_apply(directory, package_name, version, patch):
        applied.append((directory, package_name, version, patch))
        return True

    monkeypatch.setattr(validation, "_write_patched_package", fake_apply)
    fixed, error = validation._prepare_fixed_workspace({
        "source_dir": str(source),
        "package_name": "demo",
        "answer_key": {"first_patched_version": "2.0.0", "diff": "patch data"},
    }, tmp_path / "work")
    assert fixed == tmp_path / "work" / "fixed"
    assert error is None
    assert applied and applied[0][3] == {"diff": "patch data"}
