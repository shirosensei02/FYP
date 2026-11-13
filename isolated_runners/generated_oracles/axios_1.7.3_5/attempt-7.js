const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const markerDir = path.join(os.tmpdir(), 'axios-ssrf-regression-' + process.pid + '-' + Date.now());
    fs.mkdirSync(markerDir, { recursive: true });

    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    // Benign: with allowAbsoluteUrls=false, relative URL should still be combined with baseURL.
    let benignResolved;
    try {
      benignResolved = axios.getUri({
        baseURL: 'http://example.com/base/',
        url: 'ok-path',
        allowAbsoluteUrls: false
      });
    } catch (e) {
      evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    if (benignResolved !== 'http://example.com/base/ok-path') {
      evidence = 'benign_unexpected:' + benignResolved;
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    operation_completed = true;

    // Malicious: absolute URL should NOT be used directly when allowAbsoluteUrls=false.
    const attackCfg = {
      baseURL: 'http://example.com/base/',
      url: 'http://127.0.0.1:9/ssrf-probe',
      allowAbsoluteUrls: false
    };

    let maliciousResolved;
    try {
      maliciousResolved = axios.getUri(attackCfg);
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    const directAbsolute = maliciousResolved === 'http://127.0.0.1:9/ssrf-probe';
    exploit_succeeded = directAbsolute;
    evidence = 'benign=' + benignResolved + ';malicious=' + maliciousResolved;

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