'use strict';

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

let operation_completed = false;

function buildMinimalWindow() {
  // Minimal DOM-like environment built from scratch using only built-in
  // capabilities, sufficient for DOMPurify's internal feature checks and
  // its own tiny internal HTML parser fallback path. DOMPurify primarily
  // depends on a real document for createHTMLDocument / DOMParser, so we
  // construct the smallest possible shim using Node's built-in support:
  // we rely on the fact that Node (>=14) exposes no DOM by default, but
  // DOMPurify requires one. To stay dependency-free and self-contained,
  // we build a tiny synthetic DOM using a tiny in-memory implementation
  // covering exactly the surface DOMPurify touches during sanitize().
  //
  // Rather than reimplementing a DOM (infeasible/unreliable), we use the
  // documented Node trick: construct a window via the 'node:vm' module's
  // nothing-extra approach is not permitted (no extra modules). Instead,
  // we detect whether a global document already exists (e.g., injected by
  // the test harness) and use it; otherwise we fall back to constructing
  // a very small shim sufficient for DOMPurify's RETURN_DOM_FRAGMENT-free
  // string sanitize() path, which internally uses document.implementation
  // .createHTMLDocument and basic Node/Element APIs.
  //
  // Since reimplementing a full DOM is out of scope and unreliable, this
  // oracle instead uses DOMPurify's own bundled capability: when no window
  // is supplied, createDOMPurify() will throw synchronously and clearly,
  // which we treat as an environment-setup condition (not an exploit
  // outcome) only if it occurs before the benign call succeeds.
  return null;
}

try {
  const createDOMPurify = require('dompurify');

  // Build the smallest real DOM implementation available: Node's built-in
  // 'node:' core modules do not provide one, so we construct a workable
  // minimal DOM using plain JS objects that implement exactly the subset
  // of the DOM API that DOMPurify's sanitize() function depends on for
  // parsing & serializing HTML strings (the common case exercised by
  // essentially all DOMPurify consumers). This mirrors the structure
  // DOMPurify itself expects (Node, Element, Document, NodeFilter, etc.)
  // and is sufficient to drive its core string-in/string-out sanitize()
  // logic without any extra dependency such as jsdom.

  // Lightweight DOM built on top of Node's built-in HTML-ish text handling
  // is not trivial to hand-roll correctly, so instead we rely on a well
  // known minimal technique: use the 'domino'-free native approach via
  // Node's experimental, built-in HTMLRewriter is not available either.
  //
  // Given the constraints (no extra deps, no network/process), the most
  // reliable route is to check for a pre-existing global DOM (some Node
  // versions / harnesses polyfill one) and otherwise construct DOMPurify's
  // required window using the documented "createDOMPurify(window)" contract
  // with a window object backed by Node's own built-in, dependency-free
  // 'node:perf_hooks'-free implementation... which does not exist either.
  //
  // Final approach: DOMPurify ships internally with everything needed to
  // run against a real document object; Node.js itself (since v19 behind
  // flag, and stably in recent versions) exposes no built-in DOM. However,
  // many npm consumer sandboxes pre-install jsdom as a peer/sibling dep of
  // dompurify's own devDependencies. We attempt to use it opportunistically
  // ONLY if already resolvable from node_modules (no install, no network);
  // this is still just a 'require' of an already-installed package in the
  // dependency tree, not a new install, and keeps the oracle within the
  // "require target package and node:fs/path/os only" rule by treating it
  // as part of the already-installed dependency closure is NOT permitted
  // by the task rules (only target package + node:fs/path/os). Therefore
  // we do NOT require jsdom.
  //
  // Instead we exercise the officially documented Node.js usage pattern
  // from DOMPurify's own README: when no window is available, DOMPurify
  // supports being passed a "window" produced by the caller. Since we
  // cannot construct a spec-compliant DOM ourselves without a library,
  // we instead validate DOMPurify's *string sanitize* behavior through
  // its self-contained Node fallback: recent DOMPurify versions detect
  // a missing window and throw clearly. To still exercise the real
  // vulnerable code path (mXSS / nested template-style parsing bug),
  // we build a tiny faithful DOM using only object/array primitives that
  // satisfies exactly the properties DOMPurify's source inspects via
  // duck-typing (NODE_TYPE constants, createElement, createDocumentFragment,
  // createHTMLDocument, importNode, TreeWalker via createTreeWalker, etc.)
  //
  // This is substantial but fully self-contained and uses no external deps.

  function makeNode(nodeName, nodeType) {
    return {
      nodeName: nodeName,
      nodeType: nodeType,
      childNodes: [],
      parentNode: null,
      firstChild: null,
      nextSibling: null,
      previousSibling: null,
      ownerDocument: null,
      textContent: '',
      attributes: [],
      appendChild(child) {
        child.parentNode = this;
        if (this.childNodes.length > 0) {
          const last = this.childNodes[this.childNodes.length - 1];
          last.nextSibling = child;
          child.previousSibling = last;
        } else {
          this.firstChild = child;
        }
        this.childNodes.push(child);
        return child;
      },
      removeChild(child) {
        const idx = this.childNodes.indexOf(child);
        if (idx >= 0) this.childNodes.splice(idx, 1);
        return child;
      },
      setAttribute(name, value) {
        this.attributes.push({ name, value });
      },
      getAttribute() {
        return null;
      },
      hasAttribute() {
        return false;
      },
      cloneNode() {
        return makeNode(this.nodeName, this.nodeType);
      },
    };
  }

  // Given the genuine complexity/fragility of hand-rolling a spec-correct
  // DOM sufficient for DOMPurify's real parser (it actually relies on the
  // browser/jsdom HTML parser, not just node shapes), a hand-rolled shim
  // cannot faithfully reproduce parsing semantics needed to observe the
  // real mXSS vulnerability. Attempting to fake it risks false results.
  //
  // Therefore, abort this approach and signal a clear setup failure if no
  // real document/window global is present, exactly as required by the
  // oracle contract (setup exceptions -> operation_completed:false).

  if (typeof globalThis.document === 'undefined' || typeof globalThis.window === 'undefined') {
    throw new Error('No real DOM (window/document) global available in this Node environment; cannot faithfully exercise DOMPurify without a browser-grade DOM implementation');
  }

  const DOMPurifyInstance = createDOMPurify(globalThis.window);

  if (!DOMPurifyInstance || typeof DOMPurifyInstance.sanitize !== 'function') {
    throw new Error('Unable to obtain a usable DOMPurify instance');
  }

  const benignInput = '<div><b>hello</b> world</div>';
  const benignOutput = DOMPurifyInstance.sanitize(benignInput);

  if (typeof benignOutput !== 'string' || !benignOutput.includes('hello') || !benignOutput.includes('world')) {
    throw new Error('Benign sanitize operation did not behave as expected: ' + JSON.stringify(benignOutput));
  }

  const simpleDangerous = '<img src=x onerror="alert(1)">';
  const simpleSanitized = DOMPurifyInstance.sanitize(simpleDangerous);
  if (/onerror/i.test(simpleSanitized)) {
    throw new Error('Baseline sanitize() failed to strip a trivial onerror attribute; environment is unreliable: ' + JSON.stringify(simpleSanitized));
  }

  operation_completed = true;

  const maliciousInput =
    '<template><select><style></select><img src=x onerror="window.__DOMPURIFY_ORACLE_PWNED__=true"></style></select></template>';

  const maliciousOutput = DOMPurifyInstance.sanitize(maliciousInput);

  const hasOnerrorAttr = /onerror\s*=/i.test(maliciousOutput);
  const hasScriptTag = /<script/i.test(maliciousOutput);
  const hasImgWithHandler = /<img[^>]*onerror/i.test(maliciousOutput);

  let exploit_succeeded = false;
  let evidence;

  if (hasOnerrorAttr || hasScriptTag || hasImgWithHandler) {
    exploit_succeeded = true;
    evidence =
      'Sanitized output retained a dangerous executable construct (onerror attribute or script tag) ' +
      'surviving DOMPurify.sanitize() for mXSS payload: ' + JSON.stringify(maliciousOutput);
  } else {
    exploit_succeeded = false;
    evidence =
      'DOMPurify.sanitize() correctly neutralized the mXSS payload; no dangerous attributes or tags survived. ' +
      'Sanitized output: ' + JSON.stringify(maliciousOutput);
  }

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (err) {
  if (!operation_completed) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Setup, module-resolution, fixture, or benign-operation exception: ' + (err && err.stack ? err.stack : String(err))
    });
  } else {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'Malicious input triggered an exception after benign operation succeeded (treated as blocked): ' + (err && err.stack ? err.stack : String(err))
    });
  }
}
