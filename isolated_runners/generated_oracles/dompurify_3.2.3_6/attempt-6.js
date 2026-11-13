const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const createDOMPurify = require('dompurify');

  // Minimal fake window/document to exercise DOMPurify in Node without external deps.
  function makeMinimalWindow() {
    function ElementCtor() {}
    ElementCtor.prototype = {
      cloneNode: function () { return this; },
      remove: function () {},
      get nextSibling() { return null; },
      get childNodes() { return []; },
      get parentNode() { return null; }
    };

    const doc = {
      nodeType: 9,
      createElement: function () { return { content: null }; },
      createTextNode: function (t) { return { nodeType: 3, data: String(t) }; },
      implementation: { createHTMLDocument: function () { return {}; } }
    };

    return {
      document: doc,
      Element: ElementCtor,
      Node: function Node() {},
      NodeFilter: {
        SHOW_ELEMENT: 1,
        SHOW_COMMENT: 2,
        SHOW_TEXT: 4,
        SHOW_PROCESSING_INSTRUCTION: 8,
        SHOW_CDATA_SECTION: 16
      },
      HTMLFormElement: function HTMLFormElement() {},
      DOMParser: function DOMParser() {}
    };
  }

  const purify = createDOMPurify(makeMinimalWindow());
  if (!purify || typeof purify.sanitize !== 'function') {
    throw new Error('sanitize_api_missing');
  }

  const benignInput = 'plain text content';
  const benignOutput = purify.sanitize(benignInput, { SAFE_FOR_TEMPLATES: true });
  if (typeof benignOutput !== 'string' || benignOutput !== benignInput) {
    throw new Error('benign_sanitize_failed');
  }

  result.operation_completed = true;

  const maliciousInput = 'prefix ${alert(1)';
  try {
    const maliciousOutput = purify.sanitize(maliciousInput, { SAFE_FOR_TEMPLATES: true });
    const survived = typeof maliciousOutput === 'string' && maliciousOutput.indexOf('${') !== -1;
    result.exploit_succeeded = survived;
    result.evidence = JSON.stringify({ benignOutput, maliciousOutput, markerSurvived: survived });
  } catch (e) {
    result.exploit_succeeded = false;
    result.evidence = 'malicious_call_blocked';
  }
} catch (e) {
  result.operation_completed = false;
  result.exploit_succeeded = false;
  result.evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

finish();