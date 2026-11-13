const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const marker = `axios-ssrf-oracle-${process.pid}-${Date.now()}`;
  const tmpDir = path.join(os.tmpdir(), marker);

  try {
    fs.mkdirSync(tmpDir, { recursive: true });

    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    // Benign operation: absolute URL should be rejected when allowAbsoluteUrls is false.
    // We use a tiny timeout so this remains bounded even if network is unreachable.
    let benignBlocked = false;
    try {
      await axios.get('http://127.0.0.1:1/benign', {
        baseURL: 'http://example.test/base/',
        allowAbsoluteUrls: false,
        timeout: 300
      });
      evidence += 'benign_unexpected_success;';
    } catch (e) {
      const msg = String((e && e.message) || e);
      if (msg.includes('Invalid URL')) {
        benignBlocked = true;
        evidence += 'benign_blocked_invalid_url;';
      } else {
        evidence += `benign_other_error:${msg.slice(0,120)};`;
      }
    }

    if (!benignBlocked) {
      console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed: false, exploit_succeeded: false, evidence: evidence || 'benign_failed' }));
      return;
    }

    operation_completed = true;

    // Malicious operation: protocol-relative URL can bypass absolute URL checks in vulnerable versions.
    // If vulnerable, axios will treat it as network target and error with timeout/refused instead of Invalid URL.
    try {
      await axios.get('//127.0.0.1:1/evil', {
        baseURL: 'http://example.test/base/',
        allowAbsoluteUrls: false,
        timeout: 300
      });
      exploit_succeeded = true;
      evidence += 'malicious_unexpected_success;';
    } catch (e) {
      const msg = String((e && e.message) || e);
      if (msg.includes('Invalid URL')) {
        exploit_succeeded = false;
        evidence += 'malicious_blocked_invalid_url;';
      } else {
        exploit_succeeded = true;
        evidence += `malicious_not_blocked:${msg.slice(0,120)};`;
      }
    }

    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
  } catch (e) {
    const msg = String((e && e.message) || e);
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed: false, exploit_succeeded: false, evidence: `setup_or_runtime_error:${msg.slice(0,200)}` }));
  }
})();