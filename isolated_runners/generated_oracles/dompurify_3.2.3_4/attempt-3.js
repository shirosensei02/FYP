let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  // DOMPurify expects a browser-like global window in CJS usage.
  // In this harness, we provide a minimal deterministic fake to allow sanitize() calls.
  if (!global.window) {
    global.window = {
      document: {
        nodeType: 9,
        createElement: function () {
          return {
            nodeType: 1,
            nodeName: 'DIV',
            namespaceURI: 'http://www.w3.org/1999/xhtml',
            attributes: [],
            childNodes: [],
            setAttribute: function () {},
            removeAttribute: function () {},
            appendChild: function (n) { this.childNodes.push(n); return n; },
            removeChild: function (n) { return n; },
            cloneNode: function () { return this; },
            insertBefore: function (n) { return n; },
            innerHTML: ''
          };
        },
        createTextNode: function (t) { return { nodeType: 3, data: String(t) }; },
        createDocumentFragment: function () { return { nodeType: 11, childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } }; },
        body: { childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; }, innerHTML: '' },
        documentElement: { nodeName: 'HTML' },
        implementation: {
          createHTMLDocument: function () {
            return {
              documentElement: { nodeName: 'HTML' },
              body: { childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; }, innerHTML: '' },
              createElement: global.window.document.createElement,
              createTextNode: global.window.document.createTextNode,
              createDocumentFragment: global.window.document.createDocumentFragment
            };
          }
        }
      },
      Node: function Node() {},
      Element: function Element() {},
      DocumentFragment: function DocumentFragment() {},
      HTMLTemplateElement: function HTMLTemplateElement() {},
      trustedTypes: undefined
    };
  }

  const DOMPurify = require('dompurify');
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('dompurify export missing sanitize()');
  }

  const benign = '<p>hello <b>world</b></p>';
  let benignOut;
  try {
    benignOut = DOMPurify.sanitize(benign);
  } catch (e) {
    operation_completed = false;
    evidence = 'benign sanitize threw: ' + (e && e.message ? e.message : String(e));
    out();
    return;
  }

  if (typeof benignOut !== 'string' || benignOut.indexOf('hello') === -1) {
    operation_completed = false;
    evidence = 'benign sanitize unexpected output: ' + JSON.stringify(benignOut);
    out();
    return;
  }

  operation_completed = true;

  const malicious = '<math><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></math>';
  try {
    const malOut = String(DOMPurify.sanitize(malicious));
    const hasScript = /<script\b/i.test(malOut);
    exploit_succeeded = hasScript;
    evidence = 'benign=' + JSON.stringify(benignOut) + '; malicious=' + JSON.stringify(malOut) + '; hasScript=' + hasScript;
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