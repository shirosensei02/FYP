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

    // Benign: relative path should be accepted and combined with baseURL.
    let benignCfg = null;
    try {
      await axios.get('/ok', {
        baseURL: 'http://example.com/base/',
        timeout: 100,
        adapter: async (config) => {
          benignCfg = config;
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

    if (!benignCfg || benignCfg.url !== '/ok' || benignCfg.baseURL !== 'http://example.com/base/') {
      evidence = 'benign_unexpected url=' + (benignCfg && benignCfg.url) + ' base=' + (benignCfg && benignCfg.baseURL);
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    operation_completed = true;

    // Malicious: absolute URL should be blocked/neutralized when allowAbsoluteUrls=false.
    let malErr = null;
    let malCfg = null;
    try {
      await axios.get('http://127.0.0.1:9/ssrf-probe', {
        baseURL: 'http://example.com/safe/',
        allowAbsoluteUrls: false,
        timeout: 100,
        adapter: async (config) => {
          malCfg = config;
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
      const finalUrl = malCfg && typeof malCfg.url === 'string' ? malCfg.url : '';
      const finalBase = malCfg && typeof malCfg.baseURL === 'string' ? malCfg.baseURL : '';

      // Vulnerable behavior: attacker absolute URL remains directly usable.
      // Patched behavior: absolute URL is treated as relative and combined with baseURL.
      const vulnerableShape = /^http:\/\/127\.0\.0\.1:9\//.test(finalUrl);
      const patchedShape = /^http:\/\/example\.com\/safe\//.test(finalUrl) && finalUrl.indexOf('http://127.0.0.1:9/ssrf-probe') !== -1;

      exploit_succeeded = vulnerableShape && !patchedShape;
      evidence = 'benign_url=' + benignCfg.url + ';benign_base=' + benignCfg.baseURL + ';mal_url=' + finalUrl + ';mal_base=' + finalBase + ';marker=' + marker;
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