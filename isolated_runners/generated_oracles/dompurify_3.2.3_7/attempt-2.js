const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function done() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const dompurifyFactory = require('dompurify');

  // Minimal window/document stubs sufficient for factory initialization
  const NodeCtor = function Node() {};
  NodeCtor.ELEMENT_NODE = 1;
  NodeCtor.TEXT_NODE = 3;
  NodeCtor.DOCUMENT_FRAGMENT_NODE = 11;

  function makeElement(name) {
    return {
      nodeType: 1,
      nodeName: (name || 'DIV').toUpperCase(),
      namespaceURI: 'http://www.w3.org/1999/xhtml',
      attributes: [],
      childNodes: [],
      parentNode: null,
      innerHTML: '',
      textContent: '',
      setAttribute: function () {},
      removeAttribute: function () {},
      appendChild: function (n) { this.childNodes.push(n); n.parentNode = this; return n; },
      cloneNode: function () { return makeElement(name); },
      querySelector: function () { return null; },
      querySelectorAll: function () { return []; },
      getElementsByTagName: function () { return []; }
    };
  }

  const document = {
    nodeType: 9,
    body: makeElement('body'),
    documentElement: makeElement('html'),
    createElement: function (n) { return makeElement(n); },
    createElementNS: function (ns, n) { const el = makeElement(n); el.namespaceURI = ns; return el; },
    createTextNode: function (t) { return { nodeType: 3, nodeName: '#text', textContent: String(t || '') }; },
    createDocumentFragment: function () { return { nodeType: 11, nodeName: '#document-fragment', childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } }; },
    getElementsByTagName: function () { return []; },
    implementation: {
      createHTMLDocument: function () {
        return {
          nodeType: 9,
          body: makeElement('body'),
          documentElement: makeElement('html'),
          createElement: document.createElement,
          createElementNS: document.createElementNS,
          createTextNode: document.createTextNode,
          createDocumentFragment: document.createDocumentFragment,
          getElementsByTagName: document.getElementsByTagName
        };
      }
    }
  };

  const windowLike = {
    document: document,
    Node: NodeCtor,
    Element: function Element() {},
    HTMLElement: function HTMLElement() {},
    DocumentFragment: function DocumentFragment() {},
    Document: function Document() {},
    NamedNodeMap: function NamedNodeMap() {},
    HTMLTemplateElement: function HTMLTemplateElement() {},
    DOMParser: function DOMParser() {},
    navigator: { userAgent: 'oracle' }
  };

  const DOMPurify = dompurifyFactory(windowLike);

  const benign = '<p>Hello</p>';
  const benignOut = DOMPurify.sanitize(benign);
  if (typeof benignOut !== 'string' || benignOut.indexOf('Hello') === -1) {
    throw new Error('benign sanitize failed');
  }

  operation_completed = true;

  const malicious = '<svg><g/onload=alert(1)//<p></p></g></svg><math><mi//xlink:href="javascript:alert(2)">X</mi></math>';
  const malOut = DOMPurify.sanitize(malicious, { USE_PROFILES: { html: true, svg: true, mathMl: true } });

  const dangerous = /on\w+\s*=|javascript\s*:|<\s*script|xlink:href\s*=\s*['"]\s*javascript\s*:/i.test(String(malOut));
  exploit_succeeded = dangerous;
  evidence = JSON.stringify({ benignOut: benignOut, maliciousOut: String(malOut), dangerous: dangerous });
} catch (e) {
  if (operation_completed) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (e && e.message ? e.message : String(e));
  } else {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
  }
}

done();