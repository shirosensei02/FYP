'use strict';
const marker = 'next_mw_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function loadNextRequest() {
  const mod = require('next/dist/server/web/spec-extension/request');
  if (!mod || typeof mod.NextRequest !== 'function') {
    throw new Error('NextRequest constructor not found in installed next package');
  }
  return mod.NextRequest;
}

const HEADER = 'x-middleware-subrequest';
const FORGED_VALUE = ['middleware', 'middleware', 'middleware', 'middleware', 'middleware'].join(':');

function main() {
  let NextRequest;
  try {
    NextRequest = loadNextRequest();
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup_failed: could not resolve NextRequest: ' + (e && e.message)
    });
    return;
  }

  // --- Benign operation: construct an ordinary NextRequest for a normal
  // path with a harmless custom header and NO forged subrequest header.
  // Confirm the request builds correctly and the custom header round-trips
  // through NextRequest's header handling. This proves the module loads
  // and basic request construction/header access works before we attempt
  // anything malicious.
  let benignReq;
  try {
    benignReq = new NextRequest('https://example.com/dashboard', {
      headers: { 'x-oracle-marker': marker }
    });
    const echoed = benignReq.headers.get('x-oracle-marker');
    if (echoed !== marker) {
      throw new Error('benign custom header did not round-trip: got ' + JSON.stringify(echoed));
    }
    const benignSubrequestHeader = benignReq.headers.get(HEADER);
    if (benignSubrequestHeader !== null) {
      throw new Error('unexpected pre-existing x-middleware-subrequest header on benign request: ' + benignSubrequestHeader);
    }
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: ' + (e && e.message)
    });
    return;
  }

  // Benign operation succeeded -> operation_completed may become true from
  // this point forward, regardless of what happens next.

  // --- Malicious operation: construct a NextRequest for a protected path
  // carrying only the publicly-known, statically forged
  // 'x-middleware-subrequest' header value. This header requires no server
  // secret knowledge whatsoever. We then ask the package's own NextRequest
  // object (the same construct middleware code operates on) what value it
  // reports back for this header via its own header-handling logic.
  let maliciousReq;
  try {
    maliciousReq = new NextRequest('https://example.com/admin/secret', {
      headers: { [HEADER]: FORGED_VALUE }
    });
  } catch (e) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception_constructing_request: ' + (e && e.message)
    });
    return;
  }

  let observedValue;
  try {
    observedValue = maliciousReq.headers.get(HEADER);
  } catch (e) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception_reading_header: ' + (e && e.message)
    });
    return;
  }

  const survivedUnmodified = observedValue === FORGED_VALUE;

  finish({
    operation_completed: true,
    exploit_succeeded: !!survivedUnmodified,
    evidence: survivedUnmodified
      ? ('The forged static header "' + HEADER + ': ' + FORGED_VALUE + '" survived verbatim on a NextRequest built for a protected path (/admin/secret) with no sanitization or stripping by the installed next package. Because Next.js middleware (adapter.ts) trusts this client-controllable header to decide whether to skip invoking middleware for a request, an attacker can forge this exact header value to bypass middleware-based authorization checks (CVE-2025-29927).')
      : ('The forged header value was not preserved verbatim by the installed next package on request construction (observed=' + JSON.stringify(observedValue) + '); the trust-sensitive subrequest marker was stripped or altered, preventing the forged value from being usable to bypass middleware authorization.')
  });
}

try {
  main();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'unexpected_top_level_exception: ' + (e && e.message)
  }));
}
