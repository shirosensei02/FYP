'use strict';

function main() {
  let buildFullPath;

  try {
    buildFullPath = require('axios/unsafe/core/buildFullPath.js');
    if (buildFullPath && buildFullPath.default) buildFullPath = buildFullPath.default;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Failed to require buildFullPath module: ' + (e && e.message ? e.message : String(e))
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

  // --- Benign case: confirm that the normal, intended combination of
  // baseURL with a relative path works as documented. buildFullPath
  // should combine the relative path with the trusted baseURL and
  // produce a URL rooted at the trusted host. This exercises the
  // genuine public API surface (buildFullPath, used internally by
  // axios to compute the final request URL from config.baseURL and
  // config.url) with a benign, non-malicious input first.
  let benignFullPath;
  try {
    benignFullPath = buildFullPath(baseURL, '/users/list', false);
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign buildFullPath call threw: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  const benignOk = typeof benignFullPath === 'string' &&
    benignFullPath.indexOf('trusted-internal.example.com') !== -1 &&
    benignFullPath.indexOf('/users/list') !== -1;

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign result unexpected. fullPath=' + String(benignFullPath)
    }));
    return;
  }

  const operation_completed = true;

  // --- Malicious case ---
  // This reproduces CVE-2024-39338 (axios SSRF via requests to a
  // confined baseURL being redirected to an attacker-controlled
  // absolute URL). In the vulnerable version, when a caller supplies
  // an absolute URL (e.g. a path attacker-influenced data that
  // resolves to an absolute http(s) URL pointing to a different
  // host) as the `url` argument alongside a trusted `baseURL`,
  // buildFullPath (by default, allowAbsoluteUrls effectively true /
  // no protection) ignores the baseURL confinement entirely and
  // returns the attacker-supplied absolute URL verbatim, letting the
  // request escape the intended trusted host entirely (classic SSRF:
  // whatever makes the HTTP request will contact attacker.test
  // instead of trusted-internal.example.com). In the patched version,
  // when allowAbsoluteUrls=false is passed (the third argument),
  // buildFullPath must *not* return the raw absolute attacker URL;
  // instead it must combine it as a relative path under the trusted
  // baseURL, keeping the request confined to the trusted host.
  const maliciousInput = 'http://attacker.test/evil';

  let maliciousFullPath;
  let threw = false;
  let errMsg = '';
  try {
    // allowAbsoluteUrls = false: caller explicitly requests that
    // absolute URLs NOT be allowed to escape the baseURL confinement.
    maliciousFullPath = buildFullPath(baseURL, maliciousInput, false);
  } catch (e) {
    threw = true;
    errMsg = e && e.message ? e.message : String(e);
  }

  let exploit_succeeded;
  let evidence;

  if (threw) {
    exploit_succeeded = false;
    evidence = 'buildFullPath threw while combining baseURL with attacker-controlled absolute URL under allowAbsoluteUrls=false: ' + errMsg;
  } else {
    const escapedToAttacker = typeof maliciousFullPath === 'string' &&
      maliciousFullPath.indexOf('attacker.test') !== -1 &&
      maliciousFullPath.indexOf('trusted-internal.example.com') === -1;

    if (escapedToAttacker) {
      exploit_succeeded = true;
      evidence = 'buildFullPath returned attacker-controlled absolute URL verbatim despite allowAbsoluteUrls=false, escaping baseURL confinement (SSRF). Result: ' + String(maliciousFullPath);
    } else {
      exploit_succeeded = false;
      evidence = 'Attacker-controlled absolute URL was confined under trusted baseURL as expected. fullPath=' + String(maliciousFullPath);
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
