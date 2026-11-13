const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const markerDir = path.join(os.tmpdir(), 'axios-ssrf-oracle-' + process.pid + '-' + Date.now());
    fs.mkdirSync(markerDir, { recursive: true });

    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    // Benign operation: normal relative URL flow should succeed.
    let benignSeen = null;
    await axios.get('/ok', {
      baseURL: 'http://example.com/base/',
      timeout: 200,
      adapter: async (config) => {
        benignSeen = {
          url: config && config.url,
          baseURL: config && config.baseURL
        };
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

    if (!benignSeen || benignSeen.url !== '/ok') {
      evidence = 'benign_unexpected:' + JSON.stringify(benignSeen);
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    operation_completed = true;

    // Malicious operation: absolute URL should be blocked when allowAbsoluteUrls=false.
    // Use getUri to observe final resolved URL string without network.
    const cfg = {
      baseURL: 'http://example.com/safe/',
      url: 'http://127.0.0.1:9/ssrf-probe',
      allowAbsoluteUrls: false
    };

    let resolved;
    try {
      resolved = axios.getUri(cfg);
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_rejected:' + (e && e.message ? e.message : String(e));
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    const usedAbsoluteDirectly = resolved === 'http://127.0.0.1:9/ssrf-probe';
    exploit_succeeded = usedAbsoluteDirectly;
    evidence = 'resolved=' + resolved;

    try {
      fs.writeFileSync(path.join(markerDir, 'evidence.txt'), evidence, 'utf8');
    } catch (_) {}
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_exception:' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();