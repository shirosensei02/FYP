'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function main() {
  let createDOMPurify, JSDOM;
  try {
    createDOMPurify = require('dompurify');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to require dompurify: ' + String(e && e.message) });
    return;
  }

  // dompurify in Node requires a DOM window. Try to get jsdom (commonly a
  // transitive dependency of dompurify's test suite, but we only use node:fs/path/os
  // and the target package itself per constraints). If jsdom is not resolvable,
  // we cannot run the DOM-based check; report as a setup failure (not exploit).
  let JSDOMCtor;
  try {
    ({ JSDOM } = require('jsdom'));
    JSDOMCtor = JSDOM;
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'jsdom not available for DOM-based sanitize test: ' + String(e && e.message) });
    return;
  }

  const marker = 'DP_ORACLE_' + process.pid + '_' + Date.now();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dompurify-oracle-'));

  let window, DOMPurify;
  try {
    const dom = new JSDOMCtor('<!doctype html><html><body></body></html>');
    window = dom.window;
    DOMPurify = createDOMPurify(window);
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to construct jsdom window / DOMPurify instance: ' + String(e && e.message) });
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

  // Benign operation succeeded.
  const operation_completed = true;

  // --- Malicious operation ---
  let maliciousOutput;
  try {
    const payload = '<svg><template><template><style></template><img src=x onerror="window.__DP_PWNED_' + marker + '__=1"></style></template></svg>';
    maliciousOutput = DOMPurify.sanitize(payload);
  } catch (e) {
    // A thrown exception from the malicious call, after successful benign operation,
    // counts as blocked (not exploited).
    finish({ operation_completed, exploit_succeeded: false, evidence: 'Malicious sanitize call threw (treated as blocked): ' + String(e && e.message) });
    return;
  }

  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Re-parse sanitized output in a fresh DOM to check for mXSS survival.
    const checkDom = new JSDOMCtor('<!doctype html><html><body></body></html>');
    const doc = checkDom.window.document;
    doc.body.innerHTML = maliciousOutput;

    const onerrorEl = doc.querySelector('[onerror]');
    const rawHasOnerror = /onerror\s*=/i.test(maliciousOutput);
    const rawHasPwnedMarker = maliciousOutput.includes('__DP_PWNED_' + marker + '__');

    if (onerrorEl || rawHasOnerror || rawHasPwnedMarker) {
      exploit_succeeded = true;
      evidence = 'Sanitized output retained an onerror handler / executable construct after mXSS payload: ' +
        JSON.stringify(maliciousOutput).slice(0, 500) +
        (onerrorEl ? ' | DOM query [onerror] matched element.' : '');
    } else {
      evidence = 'Sanitized output contained no onerror attribute or script-triggering construct: ' +
        JSON.stringify(maliciousOutput).slice(0, 500);
    }
  } catch (e) {
    // If the verification re-parse itself throws, treat as blocked (not exploited),
    // since the benign operation already succeeded and this is just evidence gathering.
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
