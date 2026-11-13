const axios = require('axios');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const seen = [];

    const adapter = async (config) => {
      seen.push({ url: config && config.url ? String(config.url) : '', baseURL: config && config.baseURL ? String(config.baseURL) : '' });
      return {
        data: { seenUrl: config.url, seenBaseURL: config.baseURL },
        status: 200,
        statusText: 'OK',
        headers: {},
        config,
        request: null
      };
    };

    const benignResp = await axios.get('/benign', {
      baseURL: 'http://localhost',
      adapter
    });

    if (!benignResp || benignResp.status !== 200 || seen.length < 1) {
      throw new Error('benign call failed');
    }

    operation_completed = true;

    let maliciousError = null;
    try {
      await axios.get('http://attacker.test/secret', {
        baseURL: 'http://localhost/base',
        allowAbsoluteUrls: false,
        adapter,
        validateStatus: () => true
      });
    } catch (e) {
      maliciousError = e;
    }

    const benignSeen = seen[0] ? seen[0].url : '';
    const maliciousSeen = seen[1] ? seen[1].url : '';
    const maliciousIsAbsolute = /^https?:\/\//i.test(maliciousSeen);

    exploit_succeeded = maliciousIsAbsolute;

    evidence = JSON.stringify({
      benignSeen,
      maliciousSeen,
      maliciousIsAbsolute,
      maliciousError: maliciousError ? (maliciousError.message || String(maliciousError)) : null
    });
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure:' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();