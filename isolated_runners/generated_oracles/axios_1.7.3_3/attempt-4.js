'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function report(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function main() {
  const marker = 'axios_ssrf_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const tmpMarkerFile = path.join(os.tmpdir(), marker + '.txt');

  let buildFullPath;
  try {
    const mod = require('axios/unsafe/core/buildFullPath.js');
    buildFullPath = mod && (mod.default || mod);
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
    return;
  }

  if (typeof buildFullPath !== 'function') {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'buildFullPath is not a function on resolved module' });
    return;
  }

  try {
    fs.writeFileSync(tmpMarkerFile, marker, 'utf8');
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'fixture setup failed: ' + String(e && e.message) });
    return;
  }

  // --- Benign operation: relative URL against trusted baseURL, allowAbsoluteUrls=false ---
  let benignUri;
  try {
    benignUri = buildFullPath('https://safe.example.com/api/', '/resource', false);
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'benign buildFullPath call threw: ' + String(e && e.message) });
    return;
  }

  let benignHost;
  try {
    benignHost = new URL(benignUri, 'https://fallback.invalid/').hostname;
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'benign result was not a parseable URI: ' + String(benignUri) });
    return;
  }

  if (benignHost !== 'safe.example.com') {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'benign buildFullPath did not resolve to expected host; got ' + benignUri });
    return;
  }

  // Benign operation succeeded; operation_completed may become true now.
  const operation_completed = true;

  // --- Malicious operation: absolute attacker URL while allowAbsoluteUrls=false ---
  const maliciousUrl = 'http://evil.example.com/steal';

  let maliciousUri;
  try {
    maliciousUri = buildFullPath('https://safe.example.com/api/', maliciousUrl, false);
  } catch (e) {
    report({ operation_completed, exploit_succeeded: false, evidence: 'malicious buildFullPath call threw (treated as blocked): ' + String(e && e.message) });
    return;
  }

  let maliciousHost = null;
  try {
    maliciousHost = new URL(maliciousUri, 'https://fallback.invalid/').hostname;
  } catch (e) {
    report({ operation_completed, exploit_succeeded: false, evidence: 'malicious result was not a parseable URI, treated as blocked: ' + String(maliciousUri) });
    return;
  }

  let exploit_succeeded = false;
  let evidence;

  if (maliciousHost === 'evil.example.com') {
    exploit_succeeded = true;
    evidence = 'buildFullPath with allowAbsoluteUrls=false resolved baseURL https://safe.example.com/api/ with url \'' + maliciousUrl + '\' to host \'' + maliciousHost + '\' (expected host: safe.example.com) - SSRF via absolute-URL override confirmed. Marker: ' + marker;
  } else if (maliciousHost === 'safe.example.com') {
    exploit_succeeded = false;
    evidence = 'buildFullPath honored allowAbsoluteUrls=false and resolved to host \'' + maliciousHost + '\' (result: ' + maliciousUri + '); vulnerability not present. Marker: ' + marker;
  } else {
    exploit_succeeded = false;
    evidence = 'buildFullPath resolved to unexpected host \'' + maliciousHost + '\' (result: ' + maliciousUri + '); treated as not exploited. Marker: ' + marker;
  }

  try {
    fs.unlinkSync(tmpMarkerFile);
  } catch (e) {
    // non-fatal cleanup failure, ignore
  }

  report({ operation_completed, exploit_succeeded, evidence });
}

try {
  main();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected top-level exception: ' + String(e && e.message) }));
}
