let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const dompurifyModule = require('dompurify');

  let createDOMPurify;
  if (typeof dompurifyModule === 'function') {
    createDOMPurify = dompurifyModule;
  } else if (dompurifyModule && typeof dompurifyModule.default === 'function') {
    createDOMPurify = dompurifyModule.default;
  } else {
    throw new Error('Unable to resolve DOMPurify factory function from module exports');
  }

  const windowLike = {
    document: {
      nodeType: 9,
      createElement: function () {
        return {
          nodeType: 1,
          nodeName: 'DIV',
          namespaceURI: 'http://www.w3.org/1999/xhtml',
          childNodes: [],
          attributes: [],
          setAttribute: function () {},
          removeAttribute: function () {},
          appendChild: function (n) { this.childNodes.push(n); return n; },
          removeChild: function (n) { return n; },
          cloneNode: function () { return this; },
          insertBefore: function (n) { return n; },
          ownerDocument: null,
          innerHTML: ''
        };
      },
      createTextNode: function (t) { return { nodeType: 3, data: String(t) }; },
      createDocumentFragment: function () { return { nodeType: 11, childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } }; },
      implementation: {
        createHTMLDocument: function () {
          return {
            documentElement: { nodeName: 'HTML' },
            body: {
              childNodes: [],
              appendChild: function (n) { this.childNodes.push(n); return n; },
              innerHTML: ''
            },
            createElement: this._createElement,
            createTextNode: this._createTextNode,
            createDocumentFragment: this._createDocumentFragment
          };
        },
        _createElement: null,
        _createTextNode: null,
        _createDocumentFragment: null
      },
      body: { childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; }, innerHTML: '' },
      documentElement: { nodeName: 'HTML' }
    },
    Node: { ELEMENT_NODE: 1, TEXT_NODE: 3, DOCUMENT_FRAGMENT_NODE: 11 },
    Element: function Element() {},
    DocumentFragment: function DocumentFragment() {},
    HTMLTemplateElement: function HTMLTemplateElement() {},
    trustedTypes: undefined
  };

  windowLike.document.implementation._createElement = windowLike.document.createElement;
  windowLike.document.implementation._createTextNode = windowLike.document.createTextNode;
  windowLike.document.implementation._createDocumentFragment = windowLike.document.createDocumentFragment;

  const purifier = createDOMPurify(windowLike);
  if (!purifier || typeof purifier.sanitize !== 'function') {
    throw new Error('DOMPurify instance missing sanitize()');
  }

  const benignInput = '<p>safe <b>text</b></p>';
  let benignOutput;
  try {
    benignOutput = purifier.sanitize(benignInput);
  } catch (e) {
    operation_completed = false;
    evidence = 'benign sanitize threw: ' + (e && e.message ? e.message : String(e));
    finish();
    return;
  }

  if (typeof benignOutput !== 'string' || benignOutput.indexOf('safe') === -1) {
    operation_completed = false;
    evidence = 'benign sanitize returned unexpected output: ' + JSON.stringify(benignOutput);
    finish();
    return;
  }

  operation_completed = true;

  const maliciousInput = '<math><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></math>';
  try {
    const maliciousOutput = String(purifier.sanitize(maliciousInput));
    const scriptPresent = /<script\b/i.test(maliciousOutput);
    const eventAttrPresent = /on\w+\s*=\s*/i.test(maliciousOutput);
    exploit_succeeded = scriptPresent || eventAttrPresent;
    evidence = 'benign=' + JSON.stringify(benignOutput) + '; malicious=' + JSON.stringify(maliciousOutput) + '; scriptPresent=' + scriptPresent + '; eventAttrPresent=' + eventAttrPresent;
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious sanitize threw after benign success: ' + (e && e.message ? e.message : String(e));
  }

  finish();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/module error: ' + (e && e.message ? e.message : String(e));
  finish();
}