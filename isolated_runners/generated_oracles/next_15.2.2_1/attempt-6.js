'use strict';

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

// CVE-2025-29927: Next.js Middleware Authorization Bypass.
//
// Next.js uses the internal, non-client-settable header
// `x-middleware-subrequest` to detect when the server itself is recursively
// invoking middleware (to avoid infinite loops), and in that case SKIPS
// running middleware again. The vulnerability is that an external attacker
// can forge this header on an ordinary incoming request. In vulnerable
// versions, the server-side request handler trusts this attacker-supplied
// header value and treats the request as an internal subrequest, thereby
// skipping middleware entirely (bypassing auth/redirect logic implemented
// in middleware). The fix validates/strips this header using an HMAC-like
// per-build secret so client-forged values can no longer match.
//
// We exercise the real exported, documented public API surface for running
// middleware against a request: `next/dist/server/web/sandbox/sandbox.js`
// is internal/unstable across versions, so instead we use the stable public
// entrypoint `next/dist/server/next-server.js`'s exported class is also
// internal. The one genuinely stable, documented, public API that embeds
// the vulnerable/fixed decision logic and is safe to invoke without a full
// running server, filesystem project, or git repo, is the exported helper
// from `next/dist/server/web/utils.js`: `normalizeNextQueryParam` is
// unrelated. The concrete fix for this CVE lives in
// `next/dist/server/lib/router-utils/filter-internal-headers.js`
// (function `filterInternalHeaders`), which in patched builds actively
// strips the forgeable `x-middleware-subrequest` header coming from an
// external client request before internal routing logic ever sees it. In
// vulnerable builds this module/function either does not exist or does not
// strip the header, allowing the forged value to survive and reach the
// internal subrequest-detection logic that skips middleware.
//
// To avoid hard dependency on an exact file path (which differs across
// patch revisions and caused a prior failure), we resolve the function
// dynamically by scanning plausible known locations, and we treat failure
// to resolve the module as a setup/fixture failure (operation_completed
// stays false) rather than crashing.

function tryResolve(paths) {
  for (const p of paths) {
    try {
      const mod = require(p);
      if (mod && typeof mod.filterInternalHeaders === 'function') {
        return mod.filterInternalHeaders;
      }
    } catch (e) {
      // keep trying
    }
  }
  return null;
}

try {
  const candidatePaths = [
    'next/dist/server/lib/router-utils/filter-internal-headers.js',
    'next/dist/server/lib/router-utils/filter-internal-headers',
    'next/dist/server/lib/router-utils/filterInternalHeaders.js'
  ];

  const filterInternalHeaders = tryResolve(candidatePaths);

  if (!filterInternalHeaders) {
    // Module not present at all in this build (older vulnerable builds may
    // not ship this file). This is a legitimate observable difference: the
    // mitigation module is absent entirely, meaning the forged header is
    // never stripped anywhere in the public surface we can reach. We
    // simulate the equivalent benign+malicious check using the one truly
    // stable, always-present contract: the header name constant itself is
    // not exported either, so we must treat this as a setup failure per
    // the harness contract (module-resolution exception => operation
    // not completed) rather than inferring vulnerability from absence.
    throw new Error('filterInternalHeaders export not found in installed next build; cannot exercise target API');
  }

  const INTERNAL_HEADER_KEY = 'x-middleware-subrequest';

  // --- Benign call: ordinary request headers, no internal marker present.
  // This proves the exported sanitizer function runs correctly on normal
  // input without throwing and without corrupting unrelated headers. ---
  const benignHeaders = {
    host: 'example.com',
    'user-agent': 'oracle-test-agent',
    accept: 'text/html'
  };

  filterInternalHeaders(benignHeaders);

  const benignOk =
    !(INTERNAL_HEADER_KEY in benignHeaders) &&
    benignHeaders.host === 'example.com' &&
    benignHeaders['user-agent'] === 'oracle-test-agent';

  if (!benignOk) {
    throw new Error('benign_operation_unexpected_state: sanitizer altered unrelated headers or malfunctioned on ordinary input');
  }

  // Benign operation succeeded; now it is valid to mark operation_completed.
  operation_completed = true;

  // --- Malicious call: an external client forges the internal
  // x-middleware-subrequest header, attempting to make the server believe
  // this is an internal subrequest so that middleware (and any
  // authorization/redirect logic implemented inside it) gets skipped. ---
  const maliciousValue = 'middleware:middleware:middleware:middleware:middleware';
  const maliciousHeaders = {
    host: 'example.com',
    'user-agent': 'attacker-agent',
    [INTERNAL_HEADER_KEY]: maliciousValue
  };

  let threwDuringMalicious = false;
  try {
    filterInternalHeaders(maliciousHeaders);
  } catch (e) {
    threwDuringMalicious = true;
  }

  const headerStillPresent = INTERNAL_HEADER_KEY in maliciousHeaders;

  if (threwDuringMalicious) {
    exploit_succeeded = false;
    evidence = 'filterInternalHeaders threw while processing forged x-middleware-subrequest header; treated as blocked';
  } else if (headerStillPresent) {
    exploit_succeeded = true;
    evidence =
      'Forged x-middleware-subrequest header ("' +
      maliciousValue +
      '") survived filterInternalHeaders unmodified; an attacker-controlled request could still carry this header to internal routing logic that trusts it to skip middleware authorization, matching CVE-2025-29927';
  } else {
    exploit_succeeded = false;
    evidence = 'filterInternalHeaders stripped the forged x-middleware-subrequest header from the externally-originated request, neutralizing the middleware-skip authorization bypass';
  }

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (err) {
  finish({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'Unhandled exception: ' + (err && err.stack ? err.stack : String(err))
  });
}
