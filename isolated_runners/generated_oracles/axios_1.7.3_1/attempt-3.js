'use strict';

function main() {
  const axios = require('axios');
  let buildFullPathMod;
  try {
    buildFullPathMod = require('axios/unsafe/core/buildFullPath.js');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Failed to resolve buildFullPath module: ' + (e && e.message)
    }));
    return;
  }
  const buildFullPath = buildFullPathMod.default || buildFullPathMod;

  // The vulnerability (CVE-2024-28849 class / GHSA for axios SSRF via
  // allowAbsoluteUrls) is that buildFullPath(baseURL, requestedURL) ignores
  // the baseURL and uses the requestedURL verbatim whenever the requested
  // URL is "absolute", even when the caller has NOT explicitly opted into
  // that behavior. Patched axios adds an `allowAbsoluteUrls` parameter
  // (defaulting to false-safe behavior when explicitly disallowed) so that
  // passing allowAbsoluteUrls=false forces the baseURL to be respected and
  // an absolute attacker-controlled URL is combined under / rejected
  // instead of silently replacing the trusted base host.

  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  // --- Benign case: normal relative path combined with baseURL, with
  // allowAbsoluteUrls explicitly set to false (the safe/patched default
  // intent) should still produce a correctly scoped URL. ---
  const benignBase = 'http://example.com/api/';
  const benignRelative = '/users/list';

  let benignResult;
  try {
    benignResult = buildFullPath(benignBase, benignRelative, false);
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign buildFullPath call threw: ' + (e && e.message)
    }));
    return;
  }

  const benignOk = typeof benignResult === 'string' &&
    benignResult.indexOf('example.com') !== -1 &&
    benignResult.indexOf('/users/list') !== -1;

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign buildFullPath result unexpected: ' + String(benignResult)
    }));
    return;
  }

  operation_completed = true;

  // --- Malicious case: attacker-supplied absolute URL used as the
  // "requestedURL" while the application explicitly disallows absolute
  // URLs (allowAbsoluteUrls=false), intending every request to stay
  // scoped under the trusted baseURL host. In the vulnerable version,
  // buildFullPath ignores the allowAbsoluteUrls flag entirely (the
  // parameter doesn't exist / isn't honored) and returns the attacker
  // URL verbatim, bypassing baseURL confinement -> SSRF. In the patched
  // version, when allowAbsoluteUrls is explicitly false, the function
  // combines the URLs so the result stays scoped to the trusted base
  // host instead of jumping to the attacker host.
  const maliciousBase = 'http://example.com/api/';
  const maliciousAbsolute = 'http://attacker.test/evil';

  let maliciousResult;
  let threw = false;
  let errMsg = '';
  try {
    maliciousResult = buildFullPath(maliciousBase, maliciousAbsolute, false);
  } catch (e) {
    threw = true;
    errMsg = e && e.message ? e.message : String(e);
  }

  if (threw) {
    exploit_succeeded = false;
    evidence = 'Malicious buildFullPath call with allowAbsoluteUrls=false threw an exception, indicating the bypass was blocked: ' + errMsg;
  } else {
    const pointsToAttacker = typeof maliciousResult === 'string' &&
      maliciousResult.indexOf('attacker.test') !== -1;
    const staysOnBase = typeof maliciousResult === 'string' &&
      maliciousResult.indexOf('example.com') !== -1;

    if (pointsToAttacker && !staysOnBase) {
      exploit_succeeded = true;
      evidence = 'buildFullPath with allowAbsoluteUrls=false still honored the absolute attacker URL, bypassing baseURL confinement. Result: ' + String(maliciousResult);
    } else {
      exploit_succeeded = false;
      evidence = 'buildFullPath with allowAbsoluteUrls=false kept the request scoped to baseURL, rejecting the attacker absolute URL. Result: ' + String(maliciousResult);
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
