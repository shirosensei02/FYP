'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function main() {
  let createDOMPurify;
  let JSDOMWindowCtor;
  try {
    createDOMPurify = require('dompurify');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to require dompurify: ' + String(e && e.message) });
    return;
  }

  // Build a minimal browser-like global environment manually (no external deps)
  // sufficient for DOMPurify's sanitize() core logic to execute end-to-end.
  // We rely on Node's built-in parser via a tiny DOM shim based on a real
  // DOM implementation if available through globalThis, otherwise we fall
  // back to constructing an environment using the 'node:vm' module's
  // nothing extra - we instead use a tiny but faithful DOM built on top of
  // actual DOM primitives exposed by Node's experimental `HTMLElement`
  // (not guaranteed). To keep this self-contained and only use fs/path/os
  // plus dompurify, we leverage dompurify's own ability to run against a
  // provided `window`-like object if the host already has one (jsdom-less
  // environments typically do not). Many Node versions (>=20) do NOT expose
  // a global `window`. DOMPurify requires a DOM. Since we cannot require
  // extra packages, we check for a global DOM (e.g., if the test runner is
  // executed under a browser-like environment) and otherwise mark setup
  // failure explicitly (not exploit-related).

  let win = globalThis.window;
  if (!win || typeof win.document === 'undefined') {
    // Try constructing via Node's built-in `node:html`? Not available.
    // As a last resort, check if dompurify itself can run in "no window" mode
    // producing a no-op pass-through (some builds support string-only APIs).
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'No DOM/window environment available in this runtime; cannot exercise DOMPurify sanitize() end-to-end.' });
    return;
  }

  let DOMPurify;
  try {
    DOMPurify = createDOMPurify(win);
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to initialize DOMPurify with window: ' + String(e && e.message) });
    return;
  }

  const marker = 'dp_' + Date.now() + '_' + Math.random().toString(36).slice(2);

  // Benign operation first.
  let benignOutput;
  try {
    benignOutput = DOMPurify.sanitize('<b>hello world ' + marker + '</b>');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign sanitize call threw: ' + String(e && e.message) });
    return;
  }

  if (typeof benignOutput !== 'string' || benignOutput.indexOf(marker) === -1 || benignOutput.indexOf('<b>') === -1) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign sanitize call did not return expected sanitized content: ' + String(benignOutput) });
    return;
  }

  const operationCompleted = true;

  // Malicious input: a known DOMPurify mXSS bypass pattern involving nested
  // template/select/style elements that, due to parser mutation behavior,
  // can resurrect active content (onerror/onload handlers) after sanitize().
  const payload =
    '<template><template></template><select><style></template><img src=x onerror="' +
    marker +
    '_alert(1)\"></style></select></template>';

  let maliciousOutput;
  let exploitSucceeded = false;
  let evidence;
  try {
    maliciousOutput = DOMPurify.sanitize(payload);
    const lower = String(maliciousOutput).toLowerCase();
    const hasHandler = lower.indexOf('onerror=') !== -1 || lower.indexOf('onload=') !== -1;
    const hasMarkerInHandler = lower.indexOf((marker + '_alert').toLowerCase()) !== -1;
    if (hasHandler && hasMarkerInHandler) {
      exploitSucceeded = true;
      evidence = 'sanitize() output retained an active-content event handler with payload marker: ' + maliciousOutput;
    } else {
      exploitSucceeded = false;
      evidence = 'sanitize() output did not retain active-content handler; output: ' + maliciousOutput;
    }
  } catch (e) {
    // An exception on the malicious call, after benign success, counts as blocked.
    exploitSucceeded = false;
    evidence = 'Malicious sanitize call threw (treated as blocked): ' + String(e && e.message);
  }

  finish({ operation_completed: operationCompleted, exploit_succeeded: exploitSucceeded, evidence: evidence });
}

try {
  main();
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Unhandled exception: ' + String(e && e.message) });
}
