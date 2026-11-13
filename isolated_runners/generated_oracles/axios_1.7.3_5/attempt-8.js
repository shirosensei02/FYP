const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const axiosPkg = require('axios');
    const axios = axiosPkg && axiosPkg.default ? axiosPkg.default : axiosPkg;

    const markerDir = path.join(os.tmpdir(), 'axios-ssrf-oracle-' + process.pid + '-' + Date.now());
    fs.mkdirSync(markerDir, { recursive: true });

    // Benign operation: normal absolute URL allowed by default.
    let benignUri;
    try {
      benignUri = axios.getUri({
        baseURL: 'http://example.com/base/',
        url: 'http://example.org/safe-path'
      });
    } catch (e) {
      evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    if (benignUri !== 'http://example.org/safe-path') {
      evidence = 'benign_unexpected:' + benignUri;
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    operation_completed = true;

    // Malicious scenario: user-controlled absolute URL should be blocked/neutralized
    // when allowAbsoluteUrls is false.
    const maliciousInput = {
      baseURL: 'http://example.com/base/',
      url: 'http://127.0.0.1:9/ssrf-probe',
      allowAbsoluteUrls: false
    };

    let resolved;
    try {
      resolved = axios.getUri(maliciousInput);
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    const usedAttackerAbsolute = resolved === 'http://127.0.0.1:9/ssrf-probe';
    exploit_succeeded = usedAttackerAbsolute;
    evidence = 'benign=' + benignUri + ';malicious=' + resolved + ';used_attacker_absolute=' + String(usedAttackerAbsolute);

    try {
      fs.writeFileSync(path.join(markerDir, 'oracle-evidence.txt'), evidence, 'utf8');
    } catch (_) {}
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_resolution_exception:' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();