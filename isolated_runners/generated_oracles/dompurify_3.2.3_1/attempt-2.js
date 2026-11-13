'use strict';

const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const DOMPurify = require('dompurify');

  const marker = 'dompurify_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const tmpMarkerFile = path.join(os.tmpdir(), marker + '.txt');
  fs.writeFileSync(tmpMarkerFile, 'marker-file-for-oracle');

  // dompurify's main export works directly in Node without a DOM window
  // for simple string sanitization in recent versions bundled as CJS,
  // but to be safe and to exercise the real DOM-based sanitizer code
  // path (which is where the mXSS bug lives), we build a minimal DOM
  // using only Node built-ins is not possible, so we rely on dompurify's
  // own ability to create a DOM internally when no window is passed is
  // NOT supported pre-3.x in Node without jsdom. Instead we construct a
  // minimal fake window/document shim is unsafe for real DOM parsing.
  // Therefore we require dompurify as a factory and feed it a minimal
  // DOM implementation using Node's built-in 'node:vm' is disallowed by
  // constraints (process/socket/file only). Since jsdom is not available
  // as a dependency we may require (only the target package and
  // node:fs/path/os are permitted), we must use dompurify in its default
  // Node entry which auto-detects no window and throws, OR use the
  // bundled dist that already includes a DOM via 'dompurify' package's
  // own internal jsdom dependency shipped with some installs. To remain
  // strictly within allowed requires, we check if DOMPurify itself
  // exposes a usable sanitize without an explicit window (works if the
  // package was built with a bundled jsdom fallback for Node "main"
  // entry users commonly do `createDOMPurify(window)`; some versions of
  // dompurify ship a Node-compatible build that lazily requires jsdom
  // internally when no window is provided).

  let DOMPurifyInstance;
  if (typeof DOMPurify === 'function') {
    // Factory style: createDOMPurify(window) - try calling without args
    // first; some builds support this via internal jsdom usage.
    try {
      DOMPurifyInstance = DOMPurify();
    } catch (e) {
      DOMPurifyInstance = null;
    }
  } else {
    DOMPurifyInstance = DOMPurify;
  }

  if (!DOMPurifyInstance || typeof DOMPurifyInstance.sanitize !== 'function') {
    throw new Error('Unable to obtain a usable DOMPurify instance without an external DOM dependency');
  }

  // --- Benign input first ---
  const benignInput = '<div><b>hello</b> world</div>';
  const benignOutput = DOMPurifyInstance.sanitize(benignInput);

  if (typeof benignOutput !== 'string' || !benignOutput.includes('hello') || !benignOutput.includes('world')) {
    throw new Error('Benign sanitize operation did not behave as expected');
  }

  // Benign call succeeded.
  operation_completed = true;

  // --- Malicious input: mXSS payload exploiting the CSS/style-based mutation XSS
  // in DOMPurify <=3.2.3 (template/select/style nested-content mutation bypass).
  const maliciousInput =
    '<template><select><style></select><img src=x onerror="window.__DOMPURIFY_ORACLE_PWNED__=true"></style></select></template>';

  const maliciousOutput = DOMPurifyInstance.sanitize(maliciousInput);

  const rawHasOnerror = /onerror\s*=/i.test(maliciousOutput);
  const rawHasScriptTag = /<script/i.test(maliciousOutput);
  const rawHasImgTag = /<img[^>]*onerror/i.test(maliciousOutput);

  if (rawHasOnerror || rawHasScriptTag || rawHasImgTag) {
    exploit_succeeded = true;
    evidence =
      'Sanitized output retained a dangerous executable construct (onerror attribute or script tag) ' +
      'surviving DOMPurify.sanitize() for mXSS payload: ' +
      JSON.stringify(maliciousOutput);
  } else {
    exploit_succeeded = false;
    evidence =
      'DOMPurify.sanitize() correctly neutralized the mXSS payload; no dangerous attributes or tags survived. ' +
      'Sanitized output: ' + JSON.stringify(maliciousOutput);
  }

  try { fs.unlinkSync(tmpMarkerFile); } catch (e) { /* ignore cleanup errors */ }

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
