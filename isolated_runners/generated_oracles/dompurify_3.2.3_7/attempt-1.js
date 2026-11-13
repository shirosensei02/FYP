const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function printResult() {
  const out = { operation_completed, exploit_succeeded, evidence };
  console.log('ORACLE_RESULT ' + JSON.stringify(out));
}

try {
  const createDOMPurify = require('dompurify');

  function makeInertElement() {
    return {
      innerHTML: '',
      textContent: '',
      childNodes: [],
      attributes: [],
      setAttribute() {},
      removeAttribute() {},
      appendChild(node) { this.childNodes.push(node); return node; },
      cloneNode() { return makeInertElement(); },
      querySelector() { return null; },
      querySelectorAll() { return []; },
      getElementsByTagName() { return []; },
      parentNode: null,
      nodeType: 1,
      nodeName: 'DIV'
    };
  }

  const fakeDocument = {
    createElement() { return makeInertElement(); },
    createElementNS() { return makeInertElement(); },
    createTextNode(text) { return { nodeType: 3, textContent: String(text || '') }; },
    createDocumentFragment() { return makeInertElement(); },
    implementation: {
      createHTMLDocument() {
        return {
          body: makeInertElement(),
          documentElement: makeInertElement(),
          createElement: fakeDocument.createElement,
          createElementNS: fakeDocument.createElementNS,
          createTextNode: fakeDocument.createTextNode,
          createDocumentFragment: fakeDocument.createDocumentFragment
        };
      }
    }
  };

  const fakeWindow = {
    document: fakeDocument,
    Node: function Node() {},
    Element: function Element() {},
    HTMLElement: function HTMLElement() {},
    DocumentFragment: function DocumentFragment() {},
    Document: function Document() {},
    NamedNodeMap: function NamedNodeMap() {},
    HTMLTemplateElement: function HTMLTemplateElement() {},
    DOMParser: function DOMParser() {},
    navigator: { userAgent: 'oracle' }
  };

  const DOMPurify = createDOMPurify(fakeWindow);

  const benign = '<p>Hello</p>';
  const benignOut = DOMPurify.sanitize(benign);
  if (typeof benignOut !== 'string' || benignOut.length === 0 || !/Hello/.test(benignOut)) {
    throw new Error('Benign sanitize did not produce expected safe output');
  }

  operation_completed = true;

  const malicious = '<svg><g/onload=alert(1)//<p></p></g></svg><math><mi//xlink:href="javascript:alert(2)">X</mi></math>';
  const out = DOMPurify.sanitize(malicious, { USE_PROFILES: { html: true, svg: true, mathMl: true } });

  const dangerous = /on\w+\s*=|javascript\s*:|<\s*script|xlink:href\s*=\s*['"]\s*javascript\s*:/i.test(out);
  exploit_succeeded = dangerous;
  evidence = JSON.stringify({ benignOut, maliciousOut: out, dangerous });
} catch (err) {
  if (operation_completed) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (err && err.message ? err.message : String(err));
  } else {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure:' + (err && err.message ? err.message : String(err));
  }
}

printResult();