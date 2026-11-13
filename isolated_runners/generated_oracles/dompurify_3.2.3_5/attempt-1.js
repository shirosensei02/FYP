const fs = require('node:fs');
const path = require('node:path');

(function () {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const markerDir = path.join('/tmp', 'oracle-dompurify-' + Date.now() + '-' + Math.random().toString(16).slice(2));
    fs.mkdirSync(markerDir, { recursive: true });

    const createDOMPurify = require('dompurify');

    // Minimal fake window/document implementation sufficient for string-returning sanitize flow
    function makeNode(tagName) {
      return {
        nodeType: 1,
        nodeName: String(tagName || '').toUpperCase(),
        tagName: String(tagName || '').toUpperCase(),
        namespaceURI: 'http://www.w3.org/1999/xhtml',
        attributes: [],
        childNodes: [],
        parentNode: null,
        ownerDocument: null,
        firstChild: null,
        nextSibling: null,
        previousSibling: null,
        remove: function () {},
        cloneNode: function () { return makeNode(this.tagName); },
        appendChild: function (n) { this.childNodes.push(n); n.parentNode = this; this.firstChild = this.childNodes[0] || null; return n; },
        removeChild: function (n) { this.childNodes = this.childNodes.filter(function (x) { return x !== n; }); this.firstChild = this.childNodes[0] || null; return n; },
        setAttribute: function () {},
        getAttribute: function () { return null; },
        hasAttribute: function () { return false; },
        removeAttribute: function () {},
        querySelectorAll: function () { return []; },
        getElementsByTagName: function () { return []; },
        getElementsByTagNameNS: function () { return []; },
        innerHTML: '',
        textContent: ''
      };
    }

    const document = {
      nodeType: 9,
      documentElement: makeNode('html'),
      body: makeNode('body'),
      implementation: {
        createHTMLDocument: function () { return document; }
      },
      createElement: function (tag) { const n = makeNode(tag); n.ownerDocument = document; return n; },
      createElementNS: function (_ns, tag) { const n = makeNode(tag); n.ownerDocument = document; return n; },
      createTextNode: function (txt) { return { nodeType: 3, data: String(txt), textContent: String(txt), parentNode: null }; },
      createDocumentFragment: function () { return { nodeType: 11, childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } }; },
      querySelectorAll: function () { return []; },
      getElementsByTagName: function () { return []; },
      getElementsByTagNameNS: function () { return []; }
    };
    document.documentElement.ownerDocument = document;
    document.body.ownerDocument = document;

    const fakeWindow = {
      document: document,
      Node: { ELEMENT_NODE: 1, TEXT_NODE: 3, COMMENT_NODE: 8, DOCUMENT_FRAGMENT_NODE: 11 },
      Element: function () {},
      HTMLElement: function () {},
      DocumentFragment: function () {},
      Document: function () {},
      ShadowRoot: function () {},
      Text: function () {},
      Comment: function () {},
      NodeFilter: { SHOW_ELEMENT: 1, SHOW_TEXT: 4, SHOW_COMMENT: 128 },
      trustedTypes: undefined,
      navigator: { userAgent: 'oracle' }
    };

    const DOMPurify = createDOMPurify(fakeWindow);

    // Benign operation first
    const benignInput = '<p>Hello <b>world</b></p>';
    const benignOut = DOMPurify.sanitize(benignInput);
    if (typeof benignOut !== 'string') {
      throw new Error('Benign sanitize did not return a string');
    }

    operation_completed = true;

    // Malicious probe payload (generic XSS vector)
    const payload = '<img src=x onerror=alert(1)><svg><g onload=alert(2)></g></svg><a href="javascript:alert(3)">x</a>';
    const out = DOMPurify.sanitize(payload);

    const lower = String(out).toLowerCase();
    const hasInlineHandler = /onerror\s*=|onload\s*=|onclick\s*=/.test(lower);
    const hasJsHref = /href\s*=\s*["']?\s*javascript:/.test(lower);

    exploit_succeeded = hasInlineHandler || hasJsHref;
    evidence = 'benign_len=' + benignOut.length + ';malicious_out=' + JSON.stringify(out).slice(0, 240) + ';handler=' + hasInlineHandler + ';js_href=' + hasJsHref + ';marker=' + markerDir;
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'exception:' + (err && err.message ? err.message : String(err));
  }

  const result = {
    operation_completed: operation_completed,
    exploit_succeeded: exploit_succeeded,
    evidence: evidence
  };

  console.log('ORACLE_RESULT ' + JSON.stringify(result));
})();
