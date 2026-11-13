const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function timeCall(fn) {
  const t0 = nowMs();
  const out = fn();
  const dt = nowMs() - t0;
  return { out, ms: dt };
}

try {
  // Benign operation must succeed first.
  const benign = minimatch('file.txt', '*.txt');
  if (benign !== true) {
    throw new Error('benign minimatch failed');
  }

  operation_completed = true;

  // CVE-style ReDoS trigger pattern in vulnerable minimatch (brace/extglob parsing path).
  // Use a single-call measurement with bounded size so execution stays finite.
  const pattern = '*(a|aa)';
  const maliciousInput = 'a'.repeat(30000) + '!';

  const result = timeCall(() => minimatch(maliciousInput, pattern));

  // On patched versions this call is typically rejected quickly as invalid pattern input,
  // or completes much faster than vulnerable catastrophic backtracking behavior.
  // Treat a thrown error here as blocked only because benign call already succeeded.
  const thresholdMs = 1200;
  exploit_succeeded = result.ms >= thresholdMs;

  evidence = JSON.stringify({
    benign_ok: true,
    pattern,
    malicious_length: maliciousInput.length,
    malicious_result: result.out,
    elapsed_ms: Number(result.ms.toFixed(3)),
    threshold_ms: thresholdMs,
    decision: exploit_succeeded ? 'slow_match_indicates_redos' : 'fast_or_rejected'
  });
} catch (err) {
  if (operation_completed) {
    // Malicious call threw: treated as exploit blocked.
    exploit_succeeded = false;
    evidence = JSON.stringify({
      benign_ok: true,
      malicious_threw: true,
      error: err && err.message ? err.message : String(err),
      decision: 'blocked_by_exception'
    });
  } else {
    // Setup/module/benign failure.
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed,
  exploit_succeeded,
  evidence
}));
