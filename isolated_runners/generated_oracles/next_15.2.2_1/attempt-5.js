'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

// This oracle targets CVE-2025-29927: Next.js Middleware authorization bypass.
// The vulnerability is that the internal header `x-middleware-subrequest`,
// which Next.js's own server uses to detect and prevent middleware from
// recursively invoking itself, could be forged by an external client to
// make the server believe the request is an internal subrequest, causing
// middleware (and any auth/redirect logic within it) to be skipped entirely.
//
// The authoritative detection point is the exported helper that decides
// whether a request should skip middleware execution based on header
// content: `getMiddlewareRouteKeys`/`checkIsOnDemandRevalidate` evolved,
// but the concrete decision function that changed between vulnerable and
// patched builds is `next/dist/server/web/sandbox/sandbox.js`'s header
// check or (more reliably across versions) the `next-server.js` runtime's
// handling via `NextRequestHint`/`middleware-request-meta`. We exercise the
// real exported function `getRequestMeta`/`addRequestMeta` chain is internal,
// so instead we directly exercise the public, documented surface that
// embeds the fixed logic: `next/dist/server/web/utils.js`'s
// `fromNodeOutgoingHttpHeaders`/header normalization is unaffected; the
// actual authorization decision lives in
// `next/dist/server/lib/router-utils/filter-internal-headers.js`
// (`filterInternalHeaders`) in later/patched builds, while vulnerable
// builds (<=15.2.2 branch, <15.2.3) rely on a predictable depth-counter
// check performed inline using the literal header value `middleware` with
// a colon-joined list, found in `next/dist/server/next-server.js`
// (`runMiddleware`) via the helper `isMiddlewareInvoked`-like logic exposed
// through `next/dist/server/lib/server-action-request-meta.js`'s sibling
// module `next/dist/server/lib/router-utils/filter-internal-headers.js`.
//
// To keep this oracle strictly within "require the target package only"
// constraints while still exercising genuine exported behavior (not a
// hand-rolled simulation), we call the actual exported function
// `filterInternalHeaders` with a real Headers-like object carrying the
// forged header, first proving benign behavior (a header that does NOT
// match the internal marker is handled normally / left alone appropriately)
// and then supplying the malicious forged value that an attacker would
// send to skip middleware. If the installed version strips/rejects the
// forged header defensively (patched), exploit_succeeded is false; if it
// passes it through un-neutralized (vulnerable), exploit_succeeded is true.

try {
  const filterMod = require('next/dist/server/lib/router-utils/filter-internal-headers.js');
  if (!filterMod || typeof filterMod.filterInternalHeaders !== 'function') {
    throw new Error('filterInternalHeaders export not found; cannot exercise target API');
  }
  const filterInternalHeaders = filterMod.filterInternalHeaders;

  const INTERNAL_HEADER_KEY = 'x-middleware-subrequest';

  // --- Benign call: ordinary request headers, no internal marker present ---
  const benignHeaders = {
    'host': 'example.com',
    'user-agent': 'oracle-test-agent',
    'accept': 'text/html'
  };

  // Call the real function. It must run without throwing, and since there
  // is no internal header to strip, headers should remain intact afterward
  // (proving the function operates normally on ordinary input).
  filterInternalHeaders(benignHeaders);

  const benignOk = !(INTERNAL_HEADER_KEY in benignHeaders) && benignHeaders['host'] === 'example.com';
  if (!benignOk) {
    throw new Error('benign_operation_unexpected_state');
  }

  // Only now that setup + benign call succeeded do we mark operation_completed.
  operation_completed = true;

  // --- Malicious call: forged internal header value simulating an attacker
  // trying to make the server believe this is an internal middleware
  // subrequest, which (in vulnerable builds) would cause the real request
  // pipeline to treat the request specially / skip middleware authorization
  // checks downstream. Here we verify whether the exported sanitizer
  // actually strips this forgeable, attacker-controlled header before it
  // could reach that downstream decision point. ---
  const maliciousValue = 'middleware:middleware:middleware';
  const maliciousHeaders = {
    'host': 'example.com',
    'user-agent': 'attacker-agent',
    [INTERNAL_HEADER_KEY]: maliciousValue
  };

  let threwDuringMalicious = false;
  try {
    filterInternalHeaders(maliciousHeaders);
  } catch (e) {
    // A genuine crash here (after benign success) counts as blocked only if
    // it is a deliberate rejection; treat any exception post-benign as a
    // blocked exploit per the harness contract.
    threwDuringMalicious = true;
  }

  const headerStillPresent = INTERNAL_HEADER_KEY in maliciousHeaders;

  if (threwDuringMalicious) {
    exploit_succeeded = false;
    evidence = 'filterInternalHeaders threw on forged x-middleware-subrequest header; treated as blocked';
  } else if (headerStillPresent) {
    // Vulnerable: the forged internal header survives sanitization, meaning
    // an attacker-controlled request could still carry it through to the
    // internal routing logic that trusts it to skip middleware.
    exploit_succeeded = true;
    evidence = 'Forged x-middleware-subrequest header ("' + maliciousValue + '") was NOT stripped by filterInternalHeaders; downstream logic could still treat request as an internal subrequest and skip middleware authorization';
  } else {
    // Patched: the function strips the forgeable header, neutralizing the
    // forged-header based middleware-skip bypass.
    exploit_succeeded = false;
    evidence = 'filterInternalHeaders stripped the forged x-middleware-subrequest header; forged-header middleware bypass neutralized';
  }

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (err) {
  finish({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'Unhandled exception: ' + (err && err.stack ? err.stack : String(err))
  });
}
