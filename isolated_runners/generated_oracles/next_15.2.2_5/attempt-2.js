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
  const marker = path.join(os.tmpdir(), 'next-mw-oracle-' + Date.now() + '-' + Math.random().toString(16).slice(2));
  try {
    fs.mkdirSync(marker, { recursive: true });

    let NextRequest;
    try {
      ({ NextRequest } = require('next/server'));
    } catch (e) {
      evidence = 'module_resolution_failed:' + (e && e.message ? e.message : String(e));
      return finish();
    }

    if (typeof NextRequest !== 'function') {
      evidence = 'missing_NextRequest_export';
      return finish();
    }

    // Benign: construct a normal request and verify ordinary header behavior.
    try {
      const benign = new NextRequest('https://example.test/protected', {
        headers: { 'x-normal': 'ok' }
      });
      const v = benign.headers.get('x-normal');
      if (v !== 'ok') {
        evidence = 'benign_operation_failed:header_mismatch';
        return finish();
      }
    } catch (e) {
      evidence = 'benign_exception:' + (e && e.message ? e.message : String(e));
      return finish();
    }

    operation_completed = true;

    // Malicious: user-forged middleware-internal header.
    // Vulnerable versions keep this header; patched versions strip/ignore it.
    try {
      const attack = new NextRequest('https://example.test/protected', {
        headers: {
          'x-middleware-subrequest': '1',
          'x-normal': 'ok2'
        }
      });

      const forgedSeen = attack.headers.get('x-middleware-subrequest');
      const normalSeen = attack.headers.get('x-normal');

      exploit_succeeded = forgedSeen !== null && forgedSeen !== '';
      evidence = exploit_succeeded
        ? 'forged_header_preserved:' + String(forgedSeen) + '|normal=' + String(normalSeen)
        : 'forged_header_blocked|normal=' + String(normalSeen);

      fs.writeFileSync(path.join(marker, 'result.txt'), evidence);
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
