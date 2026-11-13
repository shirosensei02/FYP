'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function fail(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function main() {
  const marker = 'axios_ssrf_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const tmpMarkerFile = path.join(os.tmpdir(), marker + '.txt');

  let axios;
  try {
    axios = require('axios');
    if (axios && axios.default) {
      axios = axios.default && axios.default.getUri ? axios.default : axios;
    }
  } catch (e) {
    fail({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
    return;
  }

  try {
    fs.writeFileSync(tmpMarkerFile, marker, 'utf8');
  } catch (e) {
    fail({ operation_completed: false, exploit_succeeded: false, evidence: 'fixture setup failed: ' + String(e && e.message) });
    return;
  }

  let benignUri;
  try {
    if (!axios || typeof axios.getUri !== 'function') {
      fail({ operation_completed: false, exploit_succeeded: false, evidence: 'axios.getUri is not a function on resolved module' });
      return;
    }
    benignUri = axios.getUri({
      baseURL: 'https://safe.example.com/api/',
      url: '/resource'
    });
  } catch (e) {
    fail({ operation_completed: false, exploit_succeeded: false, evidence: 'benign getUri call threw: ' + String(e && e.message) });
    return;
  }

  let benignHost;
  try {
    benignHost = new URL(benignUri, 'https://fallback.invalid/').hostname;
  } catch (e) {
    fail({ operation_completed: false, exploit_succeeded: false, evidence: 'benign result was not a parseable URI: ' + String(benignUri) });
    return;
  }

  if (benignHost !== 'safe.example.com') {
    fail({ operation_completed: false, exploit_succeeded: false, evidence: 'benign getUri did not resolve to expected host; got ' + benignUri });
    return;
  }

  // Benign operation succeeded; now operation_completed may become true.
  const operation_completed = true;

  let maliciousUri;
  let exploit_succeeded = false;
  let evidence;

  try {
    maliciousUri = axios.getUri({
      baseURL: 'https://safe.example.com/api/',
      url: '//evil.example.com/steal'
    });
  } catch (e) {
    // Throwing on this input is an acceptable "blocked" outcome for the fixed package,
    // as long as setup/benign succeeded (already established above).
    evidence = 'malicious getUri call threw (treated as blocked): ' + String(e && e.message);
    fail({ operation_completed, exploit_succeeded: false, evidence });
    return;
  }

  let maliciousHost = null;
  try {
    maliciousHost = new URL(maliciousUri, 'https://fallback.invalid/').hostname;
  } catch (e) {
    evidence = 'malicious result was not a parseable URI, treated as blocked: ' + String(maliciousUri);
    fail({ operation_completed, exploit_succeeded: false, evidence });
    return;
  }

  if (maliciousHost === 'evil.example.com') {
    exploit_succeeded = true;
    evidence = 'getUri resolved baseURL https://safe.example.com/api/ with url //evil.example.com/steal to host \'' + maliciousHost + '\' (expected host: safe.example.com) - SSRF confirmed. Marker: ' + marker;
  } else {
    exploit_succeeded = false;
    evidence = 'getUri resolved to host \'' + maliciousHost + '\', baseURL host was preserved - vulnerability not present. Marker: ' + marker;
  }

  try {
    fs.unlinkSync(tmpMarkerFile);
  } catch (e) {
    // non-fatal cleanup failure, ignore
  }

  fail({ operation_completed, exploit_succeeded, evidence });
}

try {
  main();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected top-level exception: ' + String(e && e.message) }));
}
