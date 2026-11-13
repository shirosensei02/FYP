const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function timedMatch(input, pattern) {
  const t0 = nowMs();
  const res = minimatch(input, pattern);
  const dt = nowMs() - t0;
  return { res, ms: dt };
}

try {
  // Benign operation first
  const benign = minimatch('hello.txt', '*.txt');
  if (benign !== true) {
    throw new Error('benign operation failed');
  }

  operation_completed = true;

  // ReDoS-focused bounded test: compare a safe baseline pattern vs known problematic pattern
  // on similarly structured inputs to compute a slowdown ratio.
  const n = 1200;
  const input = 'a'.repeat(n) + '!';

  const baselinePattern = 'a*';
  const maliciousPattern = '*(a|aa)';

  const base = timedMatch(input, baselinePattern);
  const mal = timedMatch(input, maliciousPattern);

  const baselineMs = Math.max(base.ms, 0.001);
  const ratio = mal.ms / baselineMs;

  // Vulnerable versions should show very large relative slowdown.
  // Patched versions should not.
  const ratioThreshold = 25;
  const absoluteFloorMs = 40;
  exploit_succeeded = ratio >= ratioThreshold && mal.ms >= absoluteFloorMs;

  evidence = JSON.stringify({
    benign_ok: true,
    input_length: input.length,
    baseline_pattern: baselinePattern,
    malicious_pattern: maliciousPattern,
    baseline_result: base.res,
    malicious_result: mal.res,
    baseline_ms: Number(base.ms.toFixed(3)),
    malicious_ms: Number(mal.ms.toFixed(3)),
    ratio: Number(ratio.toFixed(2)),
    ratio_threshold: ratioThreshold,
    absolute_floor_ms: absoluteFloorMs,
    decision: exploit_succeeded ? 'redos_detected' : 'no_redos_detected'
  });
} catch (err) {
  if (operation_completed) {
    exploit_succeeded = false;
    evidence = JSON.stringify({
      benign_ok: true,
      malicious_threw: true,
      error: err && err.message ? err.message : String(err),
      decision: 'blocked_by_exception'
    });
  } else {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));