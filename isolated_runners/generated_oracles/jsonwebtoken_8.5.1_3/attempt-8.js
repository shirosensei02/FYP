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
  const goodSecret = 'correct-horse-battery-staple-' + marker;

  // --- Benign operation: sign with a real, non-empty HMAC secret, then verify it. ---
  const benignPayload = { sub: 'user123', role: 'guest', marker };
  let benignToken;
  try {
    benignToken = jwt.sign(benignPayload, goodSecret, { algorithm: 'HS256', expiresIn: '5m' });
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign sign failed unexpectedly: ' + String(e && e.message) });
    process.exit(0);
  }

  let benignDecoded;
  try {
    benignDecoded = jwt.verify(benignToken, goodSecret, { algorithms: ['HS256'] });
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign verify failed unexpectedly: ' + String(e && e.message) });
    process.exit(0);
  }

  if (!benignDecoded || benignDecoded.sub !== 'user123' || benignDecoded.marker !== marker) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign verify returned unexpected payload' });
    process.exit(0);
  }

  // Record a fixture artifact in tmp (not required by API but demonstrates tmp usage boundaries).
  const fixturePath = path.join(tmpDir, 'benign-token.txt');
  fs.writeFileSync(fixturePath, benignToken);

  operation_completed = true;

  // --- Malicious operation: forge an admin token signed with an EMPTY string secret, ---
  // then call jwt.sign()/jwt.verify() with that empty secret. A secure implementation
  // must treat an empty/falsy secret as invalid and refuse to sign or verify with it,
  // rather than silently performing HMAC-SHA256 with an empty key.
  const forgedPayload = { sub: 'attacker', role: 'admin', marker: marker + '-forged' };
  const emptySecret = '';

  let forgedToken = null;
  let signThrew = false;
  let signError = null;
  try {
    forgedToken = jwt.sign(forgedPayload, emptySecret, { algorithm: 'HS256', expiresIn: '5m' });
  } catch (e) {
    signThrew = true;
    signError = e;
  }

  if (signThrew || !forgedToken) {
    // Signing with an empty secret was rejected outright -> exploit blocked at sign time.
    exploit_succeeded = false;
    evidence = 'signing with empty secret was rejected (blocked): ' + String(signError && signError.message || 'sign returned no token');
    finish({ operation_completed, exploit_succeeded, evidence });
  } else {
    try {
      const forgedDecoded = jwt.verify(forgedToken, emptySecret);
      if (forgedDecoded && forgedDecoded.role === 'admin' && forgedDecoded.marker === marker + '-forged') {
        exploit_succeeded = true;
        evidence = 'jwt.sign/jwt.verify accepted an empty string secret for HS256, allowing a forged admin token to be created and verified; decoded payload: ' + JSON.stringify(forgedDecoded);
      } else {
        exploit_succeeded = false;
        evidence = 'forged token verify did not return expected forged payload: ' + JSON.stringify(forgedDecoded);
      }
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'forged token verify with empty secret was rejected (blocked): ' + String(e && e.message);
    }
    finish({ operation_completed, exploit_succeeded, evidence });
  }
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected exception: ' + String(e && e.stack || e) });
} finally {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (_) { /* ignore cleanup errors */ }
}
