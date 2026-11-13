const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const out = { operation_completed, exploit_succeeded, evidence };
  console.log('ORACLE_RESULT ' + JSON.stringify(out));
}

(async () => {
  try {
    let mod;
    try {
      mod = require('next/dist/server/web/spec-extension/cookies');
    } catch (e) {
      evidence = 'module_resolution_failed:' + (e && e.message ? e.message : String(e));
      return finish();
    }

    const { RequestCookies } = mod || {};
    if (typeof RequestCookies !== 'function') {
      evidence = 'missing_RequestCookies_export';
      return finish();
    }

    // Benign operation: construct cookie helper and perform normal read/write.
    let benignOk = false;
    try {
      const req = new Request('https://example.test/protected', {
        headers: { cookie: 'session=good; role=user' }
      });
      const cookies = new RequestCookies(req.headers);
      const before = cookies.get('session');
      cookies.set('theme', 'dark');
      const after = cookies.get('theme');
      benignOk = !!(before && before.value === 'good' && after && after.value === 'dark');
      if (!benignOk) {
        evidence = 'benign_cookie_operation_failed';
        return finish();
      }
    } catch (e) {
      evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
      return finish();
    }

    // Mark operation completed only after benign path succeeded.
    operation_completed = true;

    // Malicious input: forged internal middleware bypass header expected to be rejected/sanitized.
    // In vulnerable behavior, this internal header can survive normalization and be treated as trusted.
    try {
      const attackHeaders = new Headers({
        'x-middleware-subrequest': '1',
        'x-middleware-next': '1',
        'cookie': 'session=attacker'
      });

      // Use public WHATWG Headers operations exercised by Next internals.
      const preserved = attackHeaders.get('x-middleware-subrequest') === '1' && attackHeaders.get('x-middleware-next') === '1';

      // Oracle expectation for patched package: these spoofed internal headers should not be usable
      // from untrusted input processing paths. We treat direct preservation as exploit success.
      exploit_succeeded = preserved;
      evidence = preserved
        ? 'spoofed_internal_middleware_headers_preserved'
        : 'spoofed_internal_middleware_headers_blocked_or_sanitized';
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_blocked_with_exception:' + (e && e.message ? e.message : String(e));
    }

    return finish();
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'unrelated_exception:' + (e && e.message ? e.message : String(e));
    return finish();
  }
})();
