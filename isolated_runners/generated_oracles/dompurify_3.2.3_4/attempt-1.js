const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const result = { operation_completed, exploit_succeeded, evidence };
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const createDOMPurify = require('dompurify');

  function makeMinimalWindow() {
    return {
      document: {
        createElement: function () {
          return {
            nodeType: 1,
            nodeName: 'DIV',
            namespaceURI: 'http://www.w3.org/1999/xhtml',
            attributes: [],
            childNodes: [],
            appendChild: function (n) {
              this.childNodes.push(n);
              return n;
            },
            removeChild: function () {},
            setAttribute: function () {},
            removeAttribute: function () {},
            cloneNode: function () { return this; },
            insertBefore: function () {},
            firstChild: null,
            innerHTML: ''
          };
        },
        createTextNode: function (text) {
          return { nodeType: 3, data: String(text) };
        },
        createDocumentFragment: function () {
          return { nodeType: 11, childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } };
        },
        implementation: {
          createHTMLDocument: function () {
            return this._doc || null;
          },
          _doc: null
        },
        body: {
          innerHTML: '',
          childNodes: [],
          appendChild: function (n) { this.childNodes.push(n); return n; }
        },
        documentElement: {
          nodeName: 'HTML'
        }
      },
      Node: { ELEMENT_NODE: 1, TEXT_NODE: 3, DOCUMENT_FRAGMENT_NODE: 11 },
      Element: function () {},
      DocumentFragment: function () {},
      HTMLTemplateElement: function () {},
      trustedTypes: undefined
    };
  }

  const win = makeMinimalWindow();
  win.document.implementation._doc = win.document;

  const DOMPurify = createDOMPurify(win);

  const benignInput = '<p>Hello <b>world</b></p>';
  let benignOutput;
  try {
    benignOutput = DOMPurify.sanitize(benignInput);
  } catch (e) {
    operation_completed = false;
    evidence = 'benign sanitize threw: ' + (e && e.message ? e.message : String(e));
    finish();
    process.exit(0);
  }

  if (typeof benignOutput !== 'string' || benignOutput.indexOf('Hello') === -1) {
    operation_completed = false;
    evidence = 'benign sanitize did not return expected string';
    finish();
    process.exit(0);
  }

  operation_completed = true;

  const payload = '<svg><g/onload=alert(1)//<p>';
  let maliciousOutput;
  try {
    maliciousOutput = DOMPurify.sanitize(payload);
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious sanitize blocked via exception after successful benign call: ' + (e && e.message ? e.message : String(e));
    finish();
    process.exit(0);
  }

  const out = String(maliciousOutput);
  const stillDangerous = /onload\s*=|<script|javascript:/i.test(out);

  exploit_succeeded = stillDangerous;
  evidence = 'benign_output=' + JSON.stringify(benignOutput) + '; malicious_output=' + JSON.stringify(out) + '; dangerous=' + stillDangerous;
  finish();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/module error: ' + (e && e.message ? e.message : String(e));
  finish();
}