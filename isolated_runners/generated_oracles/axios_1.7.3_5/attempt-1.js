const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const marker = path.join(os.tmpdir(), 'axios-ssrf-oracle-' + process.pid + '-' + Date.now());

  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    // Benign operation: relative URL with explicit baseURL should resolve to base host.
    // Use tiny timeout so no network dependency is required; we only inspect final config.
    let benignCfg;
    try {
      await axios.get('/benign-path', {
        baseURL: 'http://example.com/base/',
        timeout: 20,
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
      operation_completed = false;
      evidence = 'benign call threw: ' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    if (!benignCfg || typeof benignCfg.url !== 'string' || !/^http:\/\/example\.com\//.test(benignCfg.url)) {
      operation_completed = false;
      evidence = 'benign call did not produce expected baseURL-resolved URL; got: ' + (benignCfg && benignCfg.url);
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    operation_completed = true;

    // Malicious operation: absolute URL should be blocked when allowAbsoluteUrls=false.
    // Vulnerable behavior: absolute URL still used (SSRF bypass of baseURL constraint).
    let malCfg;
    let malThrew = null;
    try {
      await axios.get('http://127.0.0.1:9/ssrf-test', {
        baseURL: 'http://example.com/safe/',
        allowAbsoluteUrls: false,
        timeout: 20,
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
      malThrew = e;
    }

    // If patched implementation rejects/throws, treat as blocked.
    if (malThrew) {
      exploit_succeeded = false;
      evidence = 'malicious call rejected: ' + (malThrew && malThrew.message ? malThrew.message : String(malThrew));
    } else {
      const finalUrl = malCfg && malCfg.url ? String(malCfg.url) : '';
      // Exploit succeeds if absolute attacker URL survives and is not constrained to base host.
      const usedAttackerAbsolute = /^http:\/\/127\.0\.0\.1:9\//.test(finalUrl);
      exploit_succeeded = usedAttackerAbsolute;
      evidence = 'benign_url=' + benignCfg.url + '; malicious_url=' + finalUrl + '; marker=' + marker;
    }

    try { fs.writeFileSync(marker, evidence); } catch (_) {}
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/module exception: ' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();
