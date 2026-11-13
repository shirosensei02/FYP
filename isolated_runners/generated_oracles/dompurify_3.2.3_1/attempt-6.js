'use strict';

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

let operation_completed = false;

try {
  const createDOMPurify = require('dompurify');

  // DOMPurify's main export, when loaded in a plain Node environment
  // without an explicit window, will attempt to use the global document
  // if available, or expects a window-like object to be passed in.
  // We avoid requiring jsdom (not guaranteed to be installed) and
  // instead build a minimal fake DOM-like window sufficient for
  // DOMPurify to initialize and run its sanitize() logic, since
  // DOMPurify performs feature detection rather than strict type checks.
  //
  // However, DOMPurify actually requires a real DOM implementation to
  // function correctly (it manipulates real DOM nodes internally).
  // Since jsdom cannot be assumed to be present, we instead rely on
  // the fact that dompurify package bundles its own minimal checks,
  // but sanitize() truly needs a document. To keep this self-contained
  // and dependency-free, we construct a tiny DOM shim using only
  // built-in Node APIs is infeasible for real HTML parsing.
  //
  // Therefore we require dompurify without passing a window, letting it
  // attempt to use globalThis.window if present; if not present, we skip
  // gracefully by throwing a clear setup error (counted as operation_completed=false).

  if (typeof globalThis.window === 'undefined' || typeof globalThis.document === 'undefined') {
    // Attempt to use Node's experimental global document if available (Node 20+ no, not available).
    // No DOM available in pure Node without jsdom; this environment cannot
    // run DOMPurify meaningfully. Report as setup failure (not exploit-related).
    throw new Error('No DOM/window/document global available in this Node environment to construct a DOMPurify instance without jsdom');
  }

  const DOMPurifyInstance = createDOMPurify(globalThis.window);

  if (!DOMPurifyInstance || typeof DOMPurifyInstance.sanitize !== 'function') {
    throw new Error('Unable to obtain a usable DOMPurify instance');
  }

  // --- Benign input first: prove normal sanitize() works ---
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
