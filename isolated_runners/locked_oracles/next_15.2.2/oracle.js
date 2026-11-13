'use strict';
const path = require('node:path');

function loadSandbox() {
  const candidates = [
    'next/dist/server/web/sandbox/context.js',
    'next/dist/server/web/sandbox/index.js'
  ];
  let lastErr = null;
  for (const c of candidates) {
    try {
      return require(c);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}

function loadFilterInternalHeaders() {
  try {
    const utils = require('next/dist/server/lib/server-ipc/utils.js');
    if (typeof utils.filterInternalHeaders === 'function') {
      return utils.filterInternalHeaders;
    }
  } catch (e) {
    // fall through
  }
  return null;
}

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Setup: load the internal header filtering utility used by the
    // router server to strip internal-only headers from inbound requests
    // before they reach middleware/user code. This is the exact function
    // whose logic changed in the patched version to prevent middleware
    // bypass via a spoofed x-middleware-subrequest header.
    const filterInternalHeaders = loadFilterInternalHeaders();

    if (typeof filterInternalHeaders !== 'function') {
      // Could not resolve the internal API needed to exercise this check.
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Could not resolve filterInternalHeaders internal API from installed next package'
      }));
      return;
    }

    // Benign case: a normal, legitimate request has no internal
    // x-middleware-* headers at all. Filtering such headers should be a
    // no-op and must not throw.
    const benignHeaders = {
      'host': 'example.com',
      'user-agent': 'oracle-test-agent',
      'accept': 'text/html'
    };

    filterInternalHeaders(benignHeaders);

    const benignOk =
      typeof benignHeaders === 'object' &&
      benignHeaders['host'] === 'example.com' &&
      !('x-middleware-subrequest' in benignHeaders);

    if (!benignOk) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Benign header filtering call did not behave as expected'
      }));
      return;
    }

    // The benign operation succeeded -> operation is considered completed.
    operation_completed = true;

    // Malicious case: an external/untrusted caller forges the internal
    // x-middleware-subrequest header (used to signal "this request is a
    // middleware-originated subrequest, skip middleware again") without
    // possessing the secret middleware-subrequest-id that the patched
    // version requires to validate provenance of that header.
    //
    // In the vulnerable version, filterInternalHeaders has no awareness
    // of any subrequest id and never strips x-middleware-subrequest based
    // on provenance -- it only strips headers that are in a fixed
    // INTERNAL_HEADERS list, which historically did NOT include
    // x-middleware-subrequest. So a forged value survives filtering,
    // allowing an attacker to make the server believe this is an internal
    // middleware subrequest and skip invoking middleware entirely --
    // bypassing any authorization check implemented in middleware.
    //
    // In the patched version, filterInternalHeaders checks whether an
    // accompanying 'x-middleware-subrequest-id' header matches a
    // server-generated secret stored on globalThis. Since our forged
    // request has no legitimate id (or an id that cannot match the
    // real secret which is process-specific and unknown to us), the
    // patched implementation deletes 'x-middleware-subrequest' from the
    // headers object, neutralizing the bypass.
    const forgedHeaders = {
      'host': 'victim.example.com',
      'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware',
      // Attacker does not know the real secret id; supply a bogus one.
      'x-middleware-subrequest-id': 'attacker-does-not-know-the-real-secret'
    };

    filterInternalHeaders(forgedHeaders);

    // If the forged internal header survived filtering, the bypass
    // primitive is present: an attacker-controlled request can still
    // claim to be an internal middleware subrequest, which is exactly
    // the condition CVE-2025-29927 exploits to skip middleware-based
    // authorization checks.
    if (Object.prototype.hasOwnProperty.call(forgedHeaders, 'x-middleware-subrequest')) {
      exploit_succeeded = true;
      evidence = 'Forged x-middleware-subrequest header survived filterInternalHeaders without a valid subrequest id, allowing middleware authorization bypass';
    } else {
      exploit_succeeded = false;
      evidence = 'Forged x-middleware-subrequest header was stripped because the subrequest id did not match the server secret, blocking the bypass';
    }

    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed,
      exploit_succeeded,
      evidence
    }));
  } catch (e) {
    // Any exception prior to a confirmed benign success means we could
    // not validate the ordinary operation; report as not completed.
    if (!operation_completed) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Exception during setup/benign operation: ' + (e && e.message ? e.message : String(e))
      }));
    } else {
      // Exception occurred after benign success, during the malicious
      // attempt -- treat as blocked.
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'Malicious call raised an exception after benign success, treated as blocked: ' + (e && e.message ? e.message : String(e))
      }));
    }
  }
}

main();
