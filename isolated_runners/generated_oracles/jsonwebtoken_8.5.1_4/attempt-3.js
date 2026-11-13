let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence || '')
  }));
}

try {
  const jwt = require('jsonwebtoken');

  // Use HS256 for benign flow so it works reliably across environments.
  const benignSecret = 'benign-secret-123';
  const benignPayload = { sub: 'user123', scope: 'read' };
  const benignToken = jwt.sign(benignPayload, benignSecret, { algorithm: 'HS256' });
  const benignOut = jwt.verify(benignToken, benignSecret);
  if (!benignOut || benignOut.sub !== 'user123' || benignOut.scope !== 'read') {
    throw new Error('benign HS256 verify failed');
  }

  operation_completed = true;

  // CVE-style bypass check: alg=none token should not verify when a key is provided.
  const forgedHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const forgedPayload = Buffer.from(JSON.stringify({ sub: 'attacker', admin: true })).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const forgedToken = forgedHeader + '.' + forgedPayload + '.';

  try {
    const out = jwt.verify(forgedToken, benignSecret);
    if (out && out.sub === 'attacker' && out.admin === true) {
      exploit_succeeded = true;
      evidence = 'alg=none token accepted by verify() with key provided';
    } else {
      exploit_succeeded = false;
      evidence = 'alg=none token returned unexpected payload';
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'alg=none token rejected: ' + (e && e.message ? e.message : String(e));
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/benign failure: ' + (e && e.message ? e.message : String(e));
}

finish();