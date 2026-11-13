let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence || '')
  }));
}

try {
  const jwt = require('jsonwebtoken');

  // Control: ordinary HS256 usage must succeed.
  const secret = 'oracle-control-secret';
  const controlPayload = { sub: 'control-user', ok: true };
  const controlToken = jwt.sign(controlPayload, secret, { algorithm: 'HS256' });
  const controlOut = jwt.verify(controlToken, secret, { algorithms: ['HS256'] });
  if (!controlOut || controlOut.sub !== 'control-user' || controlOut.ok !== true) {
    throw new Error('benign verify failed');
  }

  operation_completed = true;

  // Malicious attempt: unsigned token (alg=none) should never verify with a key provided.
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' }))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  const payload = Buffer.from(JSON.stringify({ sub: 'attacker', admin: true }))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  const forged = header + '.' + payload + '.';

  try {
    const out = jwt.verify(forged, 'non-empty-verification-key');
    if (out && out.sub === 'attacker' && out.admin === true) {
      exploit_succeeded = true;
      evidence = 'unsigned alg=none token accepted with non-empty key';
    } else {
      exploit_succeeded = true;
      evidence = 'unsigned alg=none token accepted';
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'unsigned token rejected: ' + (err && err.message ? err.message : String(err));
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/benign failure: ' + (err && err.message ? err.message : String(err));
}

emit();