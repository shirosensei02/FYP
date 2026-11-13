const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const markerDir = path.join(os.tmpdir(), 'axios-ssrf-oracle-' + process.pid + '-' + Date.now());

  try {
    fs.mkdirSync(markerDir, { recursive: true });

    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    let benignCfg = null;
    try {
      await axios.get('/benign-path', {
        baseURL: 'http://example.com/base/',
        timeout: 50,
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
      evidence = 'benign call threw: ' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    if (!benignCfg || benignCfg.url !== '/benign-path' || benignCfg.baseURL !== 'http://example.com/base/') {
      evidence = 'benign call unexpected config: url=' + (benignCfg && benignCfg.url) + ' baseURL=' + (benignCfg && benignCfg.baseURL);
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    operation_completed = true;

    let malCfg = null;
    let malErr = null;
    try {
      await axios.get('http://127.0.0.1:9/ssrf-test', {
        baseURL: 'http://example.com/safe/',
        allowAbsoluteUrls: false,
        timeout: 50,
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
      evidence = 'malicious call rejected: ' + (malErr && malErr.message ? malErr.message : String(malErr));
    } else {
      const finalUrl = malCfg && typeof malCfg.url === 'string' ? malCfg.url : '';
      const finalBase = malCfg && typeof malCfg.baseURL === 'string' ? malCfg.baseURL : '';
      const usedAbsoluteAttacker = /^http:\/\/127\.0\.0\.1:9\//.test(finalUrl);
      exploit_succeeded = usedAbsoluteAttacker;
      evidence = 'benign_url=' + benignCfg.url + '; benign_base=' + benignCfg.baseURL + '; malicious_url=' + finalUrl + '; malicious_base=' + finalBase + '; marker=' + markerDir;
    }

    try {
      fs.writeFileSync(path.join(markerDir, 'evidence.txt'), evidence, 'utf8');
    } catch (_) {}
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/module exception: ' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();