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

  let axios;
  try {
    axios = require('axios');
    if (axios && axios.default) axios = axios.default;
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
    return;
  }

  if (!axios || typeof axios.create !== 'function') {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'axios.create is not a function on resolved module' });
    return;
  }

  try {
    fs.writeFileSync(tmpMarkerFile, marker, 'utf8');
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'fixture setup failed: ' + String(e && e.message) });
    return;
  }

  let instance;
  try {
    instance = axios.create({ baseURL: 'https://safe.example.com/api/' });
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'axios.create threw during setup: ' + String(e && e.message) });
    return;
  }

  if (!instance || typeof instance.getUri !== 'function') {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'created instance does not expose getUri' });
    return;
  }

  // --- Benign operation: relative URL against trusted baseURL ---
  let benignUri;
  try {
    benignUri = instance.getUri({ url: '/resource' });
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'benign getUri call threw: ' + String(e && e.message) });
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
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'benign getUri did not resolve to expected host; got ' + benignUri });
    return;
  }

  // Benign operation succeeded; operation_completed may become true now.
  const operation_completed = true;

  // --- Malicious operation: absolute attacker URL while baseURL is configured ---
  const maliciousUrl = 'http://evil.example.com/steal';

  let maliciousUri;
  try {
    maliciousUri = instance.getUri({ url: maliciousUrl });
  } catch (e) {
    report({ operation_completed, exploit_succeeded: false, evidence: 'malicious getUri call threw (treated as blocked): ' + String(e && e.message) });
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
    evidence = 'axios.create({baseURL}).getUri with url \'' + maliciousUrl + '\' resolved to host \'' + maliciousHost + '\' (expected pinned host: safe.example.com) - SSRF via absolute-URL override of configured baseURL confirmed. Marker: ' + marker;
  } else if (maliciousHost === 'safe.example.com') {
    exploit_succeeded = false;
    evidence = 'getUri honored configured baseURL and resolved to host \'' + maliciousHost + '\' (result: ' + maliciousUri + '); absolute-URL override vulnerability not present. Marker: ' + marker;
  } else {
    exploit_succeeded = false;
    evidence = 'getUri resolved to unexpected host \'' + maliciousHost + '\' (result: ' + maliciousUri + '); treated as not exploited. Marker: ' + marker;
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
