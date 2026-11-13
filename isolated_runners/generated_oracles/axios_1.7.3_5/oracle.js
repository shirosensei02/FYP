const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    const tmpDir = path.join(os.tmpdir(), 'axios-ssrf-oracle-' + process.pid + '-' + Date.now());
    fs.mkdirSync(tmpDir, { recursive: true });

    let benignUri;
    try {
      benignUri = axios.getUri({
        baseURL: 'http://example.com/api/',
        url: 'users?id=1'
      });
    } catch (e) {
      evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    if (benignUri !== 'http://example.com/api/users?id=1') {
      evidence = 'benign_unexpected:' + String(benignUri);
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    operation_completed = true;

    const attackerUrl = 'http://127.0.0.1:9/ssrf-probe';
    let maliciousUri;
    let threw = false;
    try {
      maliciousUri = axios.getUri({
        baseURL: 'http://example.com/api/',
        url: attackerUrl,
        allowAbsoluteUrls: false
      });
    } catch (e) {
      threw = true;
      maliciousUri = 'exception:' + (e && e.message ? e.message : String(e));
    }

    const expectedBlocked = 'http://example.com/api/http://127.0.0.1:9/ssrf-probe';
    if (threw) {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_by_exception;' + maliciousUri;
    } else {
      const vulnerableBehavior = maliciousUri === attackerUrl;
      const blockedBehavior = maliciousUri === expectedBlocked;
      exploit_succeeded = vulnerableBehavior;
      evidence = 'benign=' + benignUri + ';malicious=' + maliciousUri + ';expected_blocked=' + expectedBlocked + ';vulnerable_behavior=' + String(vulnerableBehavior) + ';blocked_behavior=' + String(blockedBehavior);
    }

    try {
      fs.writeFileSync(path.join(tmpDir, 'evidence.txt'), evidence, 'utf8');
    } catch (_) {}
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_resolution_exception:' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();