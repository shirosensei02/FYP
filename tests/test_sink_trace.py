import shutil
import subprocess
from pathlib import Path

import pytest

import failure_context

TRACER = Path(__file__).resolve().parents[1] / "oracle_sink_trace.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is required")

STATS = """
var exec = require('child_process').exec
var util = require('util')
module.exports = {
  ps: function (pid, done) { exec('echo ps ' + pid, function (err, out) { done(err, out) }) },
  safe: function (pid, done) { done(null, 'ok') },
  asyncExec: util.promisify(exec)
}
"""

ORACLE = """
const stats = require('pidusage/lib/stats')
stats.safe(1, () => {})
stats.ps('1; touch /tmp/pwn', () => {
  stats.asyncExec('echo promisified').then((result) => {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: true,
      exploit_succeeded: true,
      evidence: 'promisified result keys: ' + Object.keys(result).join(',')
    }))
  })
})
"""


def _run(tmp_path, *preload):
    command = ["node", *preload, str(tmp_path / "oracle.js")]
    return subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=60)


@pytest.fixture
def vulnerable_package(tmp_path):
    library = tmp_path / "node_modules" / "pidusage" / "lib"
    library.mkdir(parents=True)
    (library / "stats.js").write_text(STATS, encoding="utf-8")
    (tmp_path / "oracle.js").write_text(ORACLE, encoding="utf-8")
    return tmp_path


def test_tracer_reports_the_package_function_that_reached_the_sink(vulnerable_package):
    result = _run(vulnerable_package, "--require", str(TRACER))

    events = failure_context.parse_sink_trace(result.stderr)
    exec_events = [event for event in events if event["argument"].startswith("echo ps")]

    assert len(exec_events) == 1, events
    assert exec_events[0]["sink"] == "child_process.exec"
    assert "touch /tmp/pwn" in exec_events[0]["argument"]
    assert "Object.ps" in exec_events[0]["frames"][0]
    assert "pidusage" in exec_events[0]["frames"][0] and "stats.js" in exec_events[0]["frames"][0]
    assert "node_modules" not in exec_events[0]["frames"][0]


def test_tracer_does_not_change_the_oracle_result(vulnerable_package):
    plain = _run(vulnerable_package)
    traced = _run(vulnerable_package, "--require", str(TRACER))

    assert plain.returncode == traced.returncode == 0
    assert plain.stdout == traced.stdout
    assert "promisified result keys: stdout,stderr" in traced.stdout


def test_tracer_ignores_calls_made_outside_the_package(tmp_path):
    (tmp_path / "oracle.js").write_text(
        "require('child_process').execSync('echo direct');"
        "console.log('ORACLE_RESULT {}');",
        encoding="utf-8",
    )

    result = _run(tmp_path, "--require", str(TRACER))

    assert failure_context.parse_sink_trace(result.stderr) == []
    assert "ORACLE_RESULT" in result.stdout
