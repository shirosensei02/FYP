const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const createDOMPurify = require('dompurify');

  const fakeNodeFilter = {
    SHOW_ELEMENT: 1,
    SHOW_COMMENT: 128,
    SHOW_TEXT: 4,
    SHOW_PROCESSING_INSTRUCTION: 64,
    SHOW_CDATA_SECTION: 8,
  };

  function makeNodeIterator() {
    return { nextNode: () => null };
  }

  function makeElement(tag) {
    const lower = String(tag || '').toLowerCase();
    const el = {
      nodeType: 1,
      nodeName: String(tag || '').toUpperCase(),
      tagName: String(tag || '').toUpperCase(),
      namespaceURI: 'http://www.w3.org/1999/xhtml',
      attributes: [],
      childNodes: [],
      parentNode: null,
      ownerDocument: null,
      textContent: '',
      innerHTML: '',
      outerHTML: '',
      firstChild: null,
      firstElementChild: null,
      hasChildNodes() { return false; },
      removeChild() {},
      appendChild() {},
      insertBefore() {},
      cloneNode() { return this; },
      remove() {},
      setAttribute() {},
      setAttributeNS() {},
      removeAttribute() {},
      getAttributeNode() { return null; },
      hasAttribute() { return false; },
      getAttribute() { return null; },
    };
    if (lower === 'template') {
      el.content = { ownerDocument: null };
    }
    return el;
  }

  const fakeDocument = {
    nodeType: 9,
    documentElement: null,
    body: null,
    currentScript: null,
    createTextNode(text) { return { nodeType: 3, nodeName: '#text', textContent: String(text || '') }; },
    createElement(tag) {
      const el = makeElement(tag);
      el.ownerDocument = this;
      if (tag === 'form') {
        Object.setPrototypeOf(el, fakeWindow.HTMLFormElement.prototype);
      }
      return el;
    },
    createDocumentFragment() {
      return { nodeType: 11, ownerDocument: this, appendChild() {}, firstChild: null };
    },
    createNodeIterator() { return makeNodeIterator(); },
    getElementsByTagName() { return [this.body || makeElement('body')]; },
    importNode(node) { return node; },
    implementation: {
      createHTMLDocument() {
        const d = Object.create(fakeDocument);
        const body = makeElement('body');
        body.ownerDocument = d;
        d.body = body;
        d.documentElement = body;
        return d;
      },
      createDocument() {
        const d = Object.create(fakeDocument);
        const tpl = makeElement('template');
        tpl.ownerDocument = d;
        d.documentElement = tpl;
        d.body = tpl;
        return d;
      },
    },
  };

  function Element() {}
  Element.prototype = makeElement('div');

  const fakeWindow = {
    document: fakeDocument,
    Element,
    NodeFilter: fakeNodeFilter,
    Node: function Node() {},
    DocumentFragment: function DocumentFragment() {},
    HTMLTemplateElement: function HTMLTemplateElement() {},
    NamedNodeMap: function NamedNodeMap() {},
    HTMLFormElement: function HTMLFormElement() {},
    DOMParser: function DOMParser() {
      this.parseFromString = function () {
        return fakeDocument.implementation.createHTMLDocument('x');
      };
    },
  };

  const rootBody = makeElement('body');
  rootBody.ownerDocument = fakeDocument;
  fakeDocument.body = rootBody;
  fakeDocument.documentElement = rootBody;

  const DOMPurify = createDOMPurify(fakeWindow);
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('sanitize_unavailable');
  }

  const benignInput = 'Hello world';
  const benignOut = DOMPurify.sanitize(benignInput, { SAFE_FOR_TEMPLATES: true });
  if (typeof benignOut !== 'string') {
    throw new Error('benign_output_not_string');
  }
  result.operation_completed = true;

  const maliciousInput = 'prefix ${PAYLOAD_WITHOUT_CLOSING_BRACE';
  try {
    const maliciousOut = DOMPurify.sanitize(maliciousInput, { SAFE_FOR_TEMPLATES: true });
    const leakedTemplateStart = typeof maliciousOut === 'string' && maliciousOut.indexOf('${') !== -1;
    result.exploit_succeeded = leakedTemplateStart;
    result.evidence = JSON.stringify({ benignOut, maliciousOut, leakedTemplateStart });
  } catch (e) {
    result.exploit_succeeded = false;
    result.evidence = 'malicious_input_rejected';
  }
} catch (e) {
  result.operation_completed = false;
  result.exploit_succeeded = false;
  result.evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

finish();