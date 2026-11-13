const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

function done() {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function makeWindow() {
  function Node() {}
  function Element() {}
  Element.prototype = Object.create(Node.prototype);

  const document = {
    nodeType: 9,
    createElement: function () {
      return {
        setAttribute: function () {},
        removeAttribute: function () {},
        hasAttribute: function () { return false; },
        getAttribute: function () { return null; }
      };
    }
  };

  return {
    document,
    Element,
    Node,
    NodeFilter: {
      SHOW_ELEMENT: 1,
      SHOW_COMMENT: 128,
      SHOW_TEXT: 4,
      SHOW_PROCESSING_INSTRUCTION: 64,
      SHOW_CDATA_SECTION: 8
    },
    HTMLFormElement: function HTMLFormElement() {},
    NamedNodeMap: function NamedNodeMap() {},
    DOMParser: function DOMParser() {},
    trustedTypes: {
      createPolicy: function () {
        return {
          createHTML: function (s) { return s; },
          createScriptURL: function (s) { return s; }
        };
      },
      getAttributeType: function () { return null; }
    }
  };
}

try {
  const createDOMPurify = require('dompurify');
  const purify = createDOMPurify(makeWindow());

  if (!purify || typeof purify.sanitize !== 'function') {
    throw new Error('sanitize_missing');
  }

  const benignIn = 'plain_text_ok';
  const benignOut = purify.sanitize(benignIn, { SAFE_FOR_TEMPLATES: true });
  if (typeof benignOut !== 'string') {
    throw new Error('benign_not_string');
  }

  result.operation_completed = true;

  const maliciousIn = 'prefix ${alert(1)';
  try {
    const maliciousOut = purify.sanitize(maliciousIn, { SAFE_FOR_TEMPLATES: true });
    const exploit = typeof maliciousOut === 'string' && maliciousOut.indexOf('${') !== -1;
    result.exploit_succeeded = exploit;
    result.evidence = JSON.stringify({ benignOut, maliciousOut, templateTokenPresent: exploit });
  } catch (e) {
    result.exploit_succeeded = false;
    result.evidence = 'malicious_rejected';
  }
} catch (e) {
  result.operation_completed = false;
  result.exploit_succeeded = false;
  result.evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

done();