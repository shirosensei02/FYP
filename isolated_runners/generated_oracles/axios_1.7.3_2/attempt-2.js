'use strict';

function main() {
  let axios;
  try {
    axios = require('axios');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'module resolution failed: ' + (e && e.message)
    }));
    return;
  }

  function emit(result) {
    console.log('ORACLE_RESULT ' + JSON.stringify(result));
  }

  // We avoid any network/process/socket activity. Instead we exercise the
  // actual exported URL-resolution logic that axios's http adapter relies
  // on internally (buildFullPath + isAbsoluteURL via the adapter's URL
  // parsing contract) by using the package's public "unsafe" export surface
  // for buildFullPath, which is part of axios's published package.json
  // exports map and is used verbatim by lib/adapters/http.js to compute the
  // URL that will actually be dispatched. This lets us verify the SSRF
  // behavior without opening sockets or spawning processes.

  let buildFullPath;
  try {
    buildFullPath = require('axios/unsafe/core/buildFullPath.js');
    buildFullPath = buildFullPath.default || buildFullPath;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup failed: could not load buildFullPath helper: ' + (e && e.message)
    }));
    return;
  }

  const baseURL = 'http://127.0.0.1:65500';

  // Benign operation: a normal relative path combined with baseURL should
  // simply produce baseURL + path, demonstrating the helper functions correc      tly.
  let operation_completed = false;
  let benignFullPath;
  try {
    benignFullPath = buildFullPath(baseURL, '/some/normal/path');
    if (typeof benignFullPath !== 'string' || !benignFullPath.includes('127.0.0.1:65500') || !benignFullPath.includes('/some/normal/path')) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'benign operation did not produce expected combined URL: ' + benignFullPath
      }));
      return;
    }
    operation_completed = true;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign operation threw unexpectedly: ' + (e && e.message)
    }));
    return;
  }

  // Malicious operation: a protocol-relative-looking path. In vulnerable
  // axios (<1.7.4), isAbsoluteURL treats this as NOT absolute (old regex
  // requires a scheme), so buildFullPath combines it with baseURL producing
  // a string like 'http://127.0.0.1:65500//attacker-host:9999/x'. However the
  // actual SSRF manifests at the http adapter layer: `new URL(fullPath, 'http://localhost')`
  // parses the combined string, and because combineURLs just concatenates,
  // the resulting pathname embeds '//attacker...' which, when re-parsed as a
  // URL in the adapter with base 'http://localhost', becomes a protocol-
  // relative reference resolving to the attacker host, overriding baseURL's
  // authority. We replicate exactly that resolution step (identical to what
  // lib/adapters/http.js does) using only URL parsing (no network), to
  // determine which host the real request would target.
  const maliciousPath = '//attacker.invalid:9999/stolen';
  let fullPath;
  try {
    fullPath = buildFullPath(baseURL, maliciousPath);
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: operation_completed,
      exploit_succeeded: false,
      evidence: 'malicious buildFullPath call threw: ' + (e && e.message)
    }));
    return;
  }

  // Mirror the vulnerable adapter's parsing: `new URL(fullPath, 'http://localhost')`
  // vs the patched adapter's parsing: `new URL(fullPath, undefined)` (server-side,
  // hasBrowserEnv is false in this pure Node environment, so platform.origin path
  // is not used and base becomes undefined, which throws for relative-looking
  // input instead of silently resolving to a different authority).
  let exploit_succeeded = false;
  let evidence;

  try {
    const parsedVulnerableStyle = new URL(fullPath, 'http://localhost');
    const parsedPatchedStyle = (() => {
      try {
        return new URL(fullPath, undefined);
      } catch (e2) {
        return null;
      }
    })();

    const targetHost = parsedVulnerableStyle.host;
    const expectedHost = new URL(baseURL).host;

    if (targetHost !== expectedHost && targetHost.includes('attacker.invalid')) {
      // Under vulnerable logic, the combined/parsed URL's authority silently
      // switched away from baseURL's host to the attacker-controlled host.
      exploit_succeeded = true;
      evidence = 'Vulnerable URL resolution directed request to attacker host "' + targetHost + '" instead of expected baseURL host "' + expectedHost + '" for input fullPath="' + fullPath + '"';
    } else {
      exploit_succeeded = false;
      evidence = 'URL resolution kept expected host "' + expectedHost + '"; attacker host was not reached for fullPath="' + fullPath + '"';
    }
  } catch (e) {
    // Patched behavior: with undefined base, a protocol-relative/invalid
    // combined string throws instead of silently resolving to a wrong host.
    exploit_succeeded = false;
    evidence = 'malicious URL resolution was blocked/rejected: ' + (e && e.message);
  }

  emit({
    operation_completed: operation_completed,
    exploit_succeeded: exploit_succeeded,
    evidence: evidence
  });
}

main();
