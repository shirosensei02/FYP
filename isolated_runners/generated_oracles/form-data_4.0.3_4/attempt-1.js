const FormData = require('form-data');

(function () {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Benign operation: instantiate and use documented API.
    const benign = new FormData();
    benign.append('field', 'value');
    const benignBoundary = benign.getBoundary();

    if (typeof benignBoundary !== 'string' || benignBoundary.length === 0) {
      throw new Error('Benign boundary generation failed');
    }

    operation_completed = true;

    // Malicious check: boundary generation should not be predictable from Math.random.
    // In vulnerable versions, boundary uses Math.random and becomes deterministic if patched.
    const originalRandom = Math.random;
    try {
      Math.random = function () { return 0; };
      const f1 = new FormData();
      const b1 = f1.getBoundary();
      const f2 = new FormData();
      const b2 = f2.getBoundary();

      // If both boundaries are equal under fixed Math.random, generator is predictably tied
      // to unsafe RNG behavior.
      exploit_succeeded = (typeof b1 === 'string' && b1.length > 0 && b1 === b2);
      evidence = 'benign_boundary_len=' + benignBoundary.length + '; b1=' + String(b1) + '; b2=' + String(b2) + '; equal_under_fixed_math_random=' + String(exploit_succeeded);
    } finally {
      Math.random = originalRandom;
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'error=' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: operation_completed,
    exploit_succeeded: exploit_succeeded,
    evidence: evidence
  }));
})();
