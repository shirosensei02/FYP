'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function buildMinimalWindow() {
  // Minimal DOM-like global environment sufficient for DOMPurify's
  // factory function to construct an instance without requiring jsdom.
  // DOMPurify internally feature-detects and will fall back gracefully
  // if advanced APIs are missing, but it needs a Document-ish object
  // with createElement/createDocumentFragment/etc. We use Node's own
  // minimal capabilities plus very small shims.
  const { JSDOM } = tryRequireJsdomOrNull();
  if (JSDOM) {
    const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
    return dom.window;
  }
  return null;
}

function tryRequireJsdomOrNull() {
  try {
    return require('jsdom');
  } catch (e) {
    return {};
  }
}

function main() {
  let createDOMPurify;
  try {
    createDOMPurify = require('dompurify');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to require dompurify: ' + String(e && e.message) });
    return;
  }

  const marker = 'DP_ORACLE_' + process.pid + '_' + Date.now();

  let tmpDir;
  try {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dompurify-oracle-'));
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to create tmp dir: ' + String(e && e.message) });
    return;
  }

  let DOMPurify;
  try {
    // Try to use jsdom if it happens to be resolvable from the consumer's
    // node_modules (not required, just opportunistic); otherwise fall back
    // to DOMPurify's own default export which, in recent versions, can
    // auto-detect and construct a minimal environment when called with
    // no arguments in a Node context that has limited DOM-like globals.
    let windowLike = null;
    try {
      windowLike = buildMinimalWindow();
    } catch (e) {
      windowLike = null;
    }

    if (windowLike) {
      DOMPurify = createDOMPurify(windowLike);
    } else {
      // No jsdom available; call factory directly. Some DOMPurify builds
      // support being invoked without a window argument by using the
      // ambient global (none in plain Node), in which case sanitize
      // will throw and we treat that as a setup/environment failure
      // rather than a benign-operation failure if it happens before
      // any sanitize call succeeds.
      DOMPurify = createDOMPurify();
    }

    if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'DOMPurify instance missing sanitize function after construction' });
      return;
    }
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to construct DOMPurify instance: ' + String(e && e.message) });
    return;
  }

  // --- Benign operation first ---
  let benignOutput;
  try {
    const benignInput = '<p>Hello <b>world</b></p> ' + marker;
    benignOutput = DOMPurify.sanitize(benignInput);
    if (typeof benignOutput !== 'string' || !benignOutput.includes('Hello') || !benignOutput.includes('world') || !benignOutput.includes(marker)) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign sanitize call did not produce expected output: ' + String(benignOutput) });
      return;
    }
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign sanitize call threw: ' + String(e && e.message) });
    return;
  }

  const operation_completed = true;

  // --- Malicious operation ---
  let maliciousOutput;
  try {
    const payload = '<svg><template><template><style></template><img src=x onerror="window.__DP_PWNED_' + marker + '__=1"></style></template></svg>';
    maliciousOutput = DOMPurify.sanitize(payload);
  } catch (e) {
    finish({ operation_completed, exploit_succeeded: false, evidence: 'Malicious sanitize call threw (treated as blocked): ' + String(e && e.message) });
    return;
  }

  let exploit_succeeded = false;
  let evidence = '';

  try {
    const rawHasOnerror = /onerror\s*=/i.test(maliciousOutput);
    const rawHasPwnedMarker = maliciousOutput.includes('__DP_PWNED_' + marker + '__');

    if (rawHasOnerror || rawHasPwnedMarker) {
      exploit_succeeded = true;
      evidence = 'Sanitized output retained an onerror handler / executable construct after mXSS payload: ' +
        JSON.stringify(maliciousOutput).slice(0, 500);
    } else {
      evidence = 'Sanitized output contained no onerror attribute or script-triggering construct: ' +
        JSON.stringify(maliciousOutput).slice(0, 500);
    }
  } catch (e) {
    evidence = 'Verification step threw while inspecting sanitized output (treated as blocked): ' + String(e && e.message);
    exploit_succeeded = false;
  }

  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (e) {
    // ignore cleanup errors
  }

  finish({ operation_completed, exploit_succeeded, evidence });
}

try {
  main();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed: false, exploit_succeeded: false, evidence: 'Uncaught top-level exception: ' + String(e && e.message) }));
}
