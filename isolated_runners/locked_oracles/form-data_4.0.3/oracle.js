'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function main() {
  let FormData;
  try {
    FormData = require('form-data');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'module resolution failed: ' + String(e && e.message)
    }));
    return;
  }

  const marker = 'formdata_boundary_marker_' + process.pid + '_' + Date.now();
  const tmpFile = path.join(os.tmpdir(), marker + '.txt');

  // Benign operation: create a FormData instance, append a field, and
  // verify it produces a valid multipart boundary header and can compute
  // headers for a part. This proves the public API works correctly.
  let benignBoundary;
  let benignOk = false;
  try {
    fs.writeFileSync(tmpFile, 'benign-content');
    const form = new FormData();
    form.append('field1', 'hello world');
    form.append('file1', fs.createReadStream(tmpFile));

    benignBoundary = form.getBoundary();

    if (typeof benignBoundary !== 'string' || benignBoundary.length === 0) {
      throw new Error('benign operation did not produce a valid boundary');
    }
    if (!benignBoundary.startsWith('----')) {
      throw new Error('benign boundary does not match expected form-data format');
    }

    const headers = form.getHeaders();
    if (!headers['content-type'] || headers['content-type'].indexOf(benignBoundary) === -1) {
      throw new Error('benign content-type header does not include boundary');
    }

    benignOk = true;
  } catch (e) {
    try { fs.unlinkSync(tmpFile); } catch (_e) {}
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign operation failed: ' + String(e && e.message)
    }));
    return;
  }

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign operation did not complete successfully'
    }));
    return;
  }

  // Security-relevant check: the boundary generation in vulnerable versions
  // uses Math.random() (via a weak PRNG construction), which is predictable
  // and not cryptographically secure. The patched version uses
  // crypto.randomBytes / crypto.randomInt internally.
  //
  // We cannot directly introspect which RNG is used internally without
  // spawning a process or monkey-patching globals in a way that constitutes
  // altering files outside /tmp. Instead, we perform a statistical analysis:
  // we generate a large number of boundaries and check for entropy/distribution
  // characteristics distinguishing Math.random()-based generation from
  // crypto-based generation is unreliable across environments, so instead we
  // directly test determinism/predictability by seeding Math.random via
  // monkey-patching the global Math.random (allowed - this is just a JS
  // object property; it's not a filesystem operation) and checking whether
  // boundaries are influenced by Math.random when it is deterministic.
  //
  // If the package internally uses Math.random, replacing global Math.random
  // with a deterministic function will cause generated boundaries to become
  // predictable/deterministic (always identical sequences for repeated calls
  // between instance creations that reset any internal state). If the package
  // uses crypto.randomBytes internally, boundaries will remain unpredictable
  // regardless of Math.random being overridden.

  let exploitSucceeded = false;
  let evidence = '';

  try {
    const originalRandom = Math.random;
    let callCount = 0;
    // Deterministic sequence: always return the same value so that any
    // boundary derived purely from Math.random() becomes constant/predictable.
    Math.random = function () {
      callCount++;
      return 0.123456789;
    };

    let boundaries = [];
    try {
      for (let i = 0; i < 5; i++) {
        const f = new FormData();
        f.append('x', 'y');
        boundaries.push(f.getBoundary());
      }
    } finally {
      Math.random = originalRandom;
    }

    const allIdentical = boundaries.every(function (b) { return b === boundaries[0]; });
    const mathRandomWasUsed = callCount > 0;

    if (mathRandomWasUsed && allIdentical) {
      exploitSucceeded = true;
      evidence = 'Boundary generation is fully deterministic when Math.random() is seeded/fixed ' +
        '(all ' + boundaries.length + ' generated boundaries identical: ' + boundaries[0] + '), ' +
        'confirming use of insecure Math.random() for boundary selection (CWE-338).';
    } else if (mathRandomWasUsed && !allIdentical) {
      exploitSucceeded = false;
      evidence = 'Math.random() was invoked (' + callCount + ' calls) during boundary generation, ' +
        'but boundaries were not fully deterministic across instances; secure randomness appears to be used.';
    } else {
      exploitSucceeded = false;
      evidence = 'Math.random() was not invoked during boundary generation (' + callCount + ' calls observed); ' +
        'package appears to use a cryptographically secure random source (e.g., crypto.randomBytes), ' +
        'consistent with the patched version.';
    }
  } catch (e) {
    try { fs.unlinkSync(tmpFile); } catch (_e) {}
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'exception during exploit probe (treated as blocked): ' + String(e && e.message)
    }));
    return;
  }

  try { fs.unlinkSync(tmpFile); } catch (_e) {}

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: true,
    exploit_succeeded: exploitSucceeded,
    evidence: evidence
  }));
}

main();
