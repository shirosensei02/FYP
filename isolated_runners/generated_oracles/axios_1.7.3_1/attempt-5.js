'use strict';

function main() {
  let axios;
  try {
    axios = require('axios');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Failed to require axios: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  let buildFullPath;
  try {
    buildFullPath = require('axios/unsafe/core/buildFullPath.js');
    if (buildFullPath && buildFullPath.default) buildFullPath = buildFullPath.default;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Failed to require internal buildFullPath module: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  if (typeof buildFullPath !== 'function') {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'buildFullPath export is not a function; cannot exercise target API'
    }));
    return;
  }

  const baseURL = 'http://trusted-internal.example.com/api/';

  // --- Benign case: a relative path combined with baseURL should
  // resolve to a URL scoped under the trusted host, with
  // allowAbsoluteUrls explicitly set to false (the documented SSRF
  // mitigation knob). ---
  let benignResult;
  try {
    benignResult = buildFullPath(baseURL, '/users/list', false);
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign buildFullPath call threw: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  const benignOk = typeof benignResult === 'string' &&
    benignResult.indexOf('trusted-internal.example.com') !== -1 &&
    benignResult.indexOf('/users/list') !== -1;

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign buildFullPath result unexpected: ' + String(benignResult)
    }));
    return;
  }

  const operation_completed = true;

  // --- Malicious case: an attacker-controlled absolute URL is supplied
  // as the relative-url argument while the caller has explicitly set
  // allowAbsoluteUrls=false, intending every resolved request URL to
  // remain confined to the trusted baseURL host. In the vulnerable
  // version (<=1.7.3), buildFullPath ignores allowAbsoluteUrls=false
  // for absolute URLs and returns the attacker URL verbatim, enabling
  // SSRF. In the patched version, when allowAbsoluteUrls is explicitly
  // false, an absolute URL is rejected (throws) instead of being
  // honored.
  const maliciousAbsolute = 'http://attacker.test/evil';

  let maliciousResult;
  let threw = false;
  let errMsg = '';
  try {
    maliciousResult = buildFullPath(baseURL, maliciousAbsolute, false);
  } catch (e) {
    threw = true;
    errMsg = e && e.message ? e.message : String(e);
  }

  let exploit_succeeded;
  let evidence;

  if (threw) {
    exploit_succeeded = false;
    evidence = 'buildFullPath with allowAbsoluteUrls=false threw an exception for an absolute attacker URL, indicating the bypass was blocked: ' + errMsg;
  } else {
    const pointsToAttacker = typeof maliciousResult === 'string' &&
      maliciousResult.indexOf('attacker.test') !== -1;
    const staysOnBase = typeof maliciousResult === 'string' &&
      maliciousResult.indexOf('trusted-internal.example.com') !== -1;

    if (pointsToAttacker && !staysOnBase) {
      exploit_succeeded = true;
      evidence = 'buildFullPath with allowAbsoluteUrls=false still honored the absolute attacker URL, bypassing baseURL confinement. Result: ' + String(maliciousResult);
    } else {
      exploit_succeeded = false;
      evidence = 'buildFullPath with allowAbsoluteUrls=false kept the result scoped to baseURL or otherwise rejected the attacker absolute URL. Result: ' + String(maliciousResult);
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed,
    exploit_succeeded,
    evidence
  }));
}

try {
  main();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'Unhandled exception in oracle script: ' + (e && e.message ? e.message : String(e))
  }));
}
