let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');
  if (typeof createDOMPurify !== 'function') {
    throw new Error('dompurify export is not a function');
  }

  function makeElement(tag) {
    const t = String(tag || '').toUpperCase();
    return {
      nodeType: 1,
      nodeName: t,
      tagName: t,
      namespaceURI: 'http://www.w3.org/1999/xhtml',
      parentNode: null,
      childNodes: [],
      attributes: [],
      _html: '',
      appendChild: function (n) { if (n) { n.parentNode = this; this.childNodes.push(n); } return n; },
      removeChild: function (n) { const i = this.childNodes.indexOf(n); if (i >= 0) this.childNodes.splice(i, 1); return n; },
      insertBefore: function (n) { return this.appendChild(n); },
      cloneNode: function () { return makeElement(t); },
      setAttribute: function (k, v) { this.attributes.push({ name: String(k), value: String(v) }); },
      getAttribute: function () { return null; },
      removeAttribute: function () {},
      hasAttribute: function () { return false; },
      querySelectorAll: function () { return []; },
      getElementsByTagName: function () { return []; },
      get firstChild() { return this.childNodes[0] || null; },
      get nextSibling() { return null; }
    };
  }

  const doc = {
    nodeType: 9,
    nodeName: '#document',
    documentElement: makeElement('html'),
    body: makeElement('body'),
    head: makeElement('head'),
    readyState: 'complete',
    createElement: function (tag) { return makeElement(tag); },
    createElementNS: function (_ns, tag) { return makeElement(tag); },
    createTextNode: function (text) { return { nodeType: 3, nodeName: '#text', data: String(text), textContent: String(text), parentNode: null }; },
    createComment: function (text) { return { nodeType: 8, nodeName: '#comment', data: String(text), parentNode: null }; },
    createDocumentFragment: function () { return { nodeType: 11, nodeName: '#document-fragment', childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } }; },
    importNode: function (n) { return n; },
    querySelectorAll: function () { return []; },
    getElementsByTagName: function () { return []; },
    addEventListener: function () {},
    removeEventListener: function () {}
  };
  doc.implementation = {
    createHTMLDocument: function () {
      const d = Object.assign({}, doc);
      d.documentElement = makeElement('html');
      d.head = makeElement('head');
      d.body = makeElement('body');
      d.documentElement.appendChild(d.head);
      d.documentElement.appendChild(d.body);
      return d;
    }
  };

  const win = {
    document: doc,
    Node: function Node() {},
    Element: function Element() {},
    HTMLElement: function HTMLElement() {},
    DocumentFragment: function DocumentFragment() {},
    HTMLTemplateElement: function HTMLTemplateElement() {},
    SVGElement: function SVGElement() {},
    MathMLElement: function MathMLElement() {},
    DOMParser: function DOMParser() {
      this.parseFromString = function () { return doc.implementation.createHTMLDocument(''); };
    },
    addEventListener: function () {},
    removeEventListener: function () {}
  };

  const DOMPurify = createDOMPurify(win);
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('failed to initialize sanitize');
  }

  const benignInput = '<p>Hello <b>world</b></p>';
  let benignOutput;
  try {
    benignOutput = String(DOMPurify.sanitize(benignInput));
  } catch (e) {
    evidence = 'benign sanitize threw: ' + (e && e.message ? e.message : String(e));
    out();
    return;
  }

  if (benignOutput.indexOf('Hello') === -1) {
    evidence = 'benign sanitize unexpected output: ' + JSON.stringify(benignOutput);
    out();
    return;
  }

  operation_completed = true;

  const maliciousInput = '<math><annotation-xml encoding="text/html"><svg><script>alert(1)</script></svg></annotation-xml></math>';
  try {
    const maliciousOutput = String(DOMPurify.sanitize(maliciousInput));
    const retainedScript = /<script\b/i.test(maliciousOutput);
    exploit_succeeded = retainedScript;
    evidence = 'benign=' + JSON.stringify(benignOutput) + '; malicious=' + JSON.stringify(maliciousOutput) + '; retainedScript=' + retainedScript;
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious sanitize threw after benign success: ' + (e && e.message ? e.message : String(e));
  }

  out();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/module error: ' + (e && e.message ? e.message : String(e));
  out();
}