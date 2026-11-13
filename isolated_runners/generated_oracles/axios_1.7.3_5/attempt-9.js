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

    const markerDir = path.join(os.tmpdir(), 'axios-ssrf-regression-' + process.pid + '-' + Date.now());
    fs.mkdirSync(markerDir, { recursive: true });

    // Benign: relative path should be combined with baseURL.
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
      evidence = 'benign_unexpected:' + benignUri;
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    operation_completed = true;

    // Malicious: absolute attacker URL with allowAbsoluteUrls:false should not remain absolute.
    const attackerUrl = 'http://127.0.0.1:9/ssrf-probe';
    let maliciousUri;
    try {
      maliciousUri = axios.getUri({
        baseURL: 'http://example.com/api/',
        url: attackerUrl,
        allowAbsoluteUrls: false
      });
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    const remainedAbsolute = maliciousUri === attackerUrl;
    exploit_succeeded = remainedAbsolute;
    evidence = 'benign=' + benignUri + ';malicious=' + maliciousUri + ';attacker_absolute_preserved=' + String(remainedAbsolute);

    try {
      fs.writeFileSync(path.join(markerDir, 'evidence.txt'), evidence, 'utf8');
    } catch (_) {}
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_resolution_exception:' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();