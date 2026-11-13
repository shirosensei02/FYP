let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');

  // Minimal DOM implementation sufficient for DOMPurify usage in Node
  function createNodeList(items) {
    const arr = items || [];
    arr.item = function (i) { return arr[i] || null; };
    return arr;
  }

  function makeElement(doc, name, ns) {
    const el = {
      nodeType: 1,
      nodeName: String(name || 'div').toUpperCase(),
      namespaceURI: ns || 'http://www.w3.org/1999/xhtml',
      ownerDocument: doc,
      attributes: [],
      childNodes: createNodeList([]),
      parentNode: null,
      _innerHTML: '',
      setAttribute: function (k, v) {
        const key = String(k);
        const val = String(v);
        const idx = this.attributes.findIndex(function (a) { return a.name === key; });
        if (idx >= 0) this.attributes[idx].value = val;
        else this.attributes.push({ name: key, value: val });
      },
      getAttribute: function (k) {
        const key = String(k);
        const a = this.attributes.find(function (x) { return x.name === key; });
        return a ? a.value : null;
      },
      removeAttribute: function (k) {
        const key = String(k);
        this.attributes = this.attributes.filter(function (a) { return a.name !== key; });
      },
      appendChild: function (n) {
        if (n && typeof n === 'object') {
          n.parentNode = this;
          this.childNodes.push(n);
        }
        return n;
      },
      removeChild: function (n) {
        const i = this.childNodes.indexOf(n);
        if (i >= 0) this.childNodes.splice(i, 1);
        return n;
      },
      cloneNode: function () {
        const c = makeElement(doc, this.nodeName, this.namespaceURI);
        c._innerHTML = this._innerHTML;
        c.attributes = this.attributes.map(function (a) { return { name: a.name, value: a.value }; });
        return c;
      },
      querySelector: function () { return null; },
      querySelectorAll: function () { return createNodeList([]); },
      getElementsByTagName: function () { return createNodeList([]); },
      get firstChild() { return this.childNodes.length ? this.childNodes[0] : null; },
      get lastChild() { return this.childNodes.length ? this.childNodes[this.childNodes.length - 1] : null; },
      get innerHTML() { return this._innerHTML; },
      set innerHTML(v) { this._innerHTML = String(v); },
      get textContent() { return this._innerHTML; },
      set textContent(v) { this._innerHTML = String(v); }
    };
    return el;
  }

  function makeDocument() {
    const doc = {
      nodeType: 9,
      contentType: 'text/html',
      childNodes: createNodeList([]),
      documentElement: null,
      body: null,
      head: null,
      implementation: null,
      createElement: function (name) { return makeElement(doc, name, 'http://www.w3.org/1999/xhtml'); },
      createElementNS: function (ns, name) { return makeElement(doc, name, ns); },
      createTextNode: function (t) { return { nodeType: 3, data: String(t), ownerDocument: doc, parentNode: null }; },
      createComment: function (t) { return { nodeType: 8, data: String(t), ownerDocument: doc, parentNode: null }; },
      createDocumentFragment: function () {
        return {
          nodeType: 11,
          childNodes: createNodeList([]),
          ownerDocument: doc,
          appendChild: function (n) { this.childNodes.push(n); return n; },
          cloneNode: function () { return this; }
        };
      },
      getElementsByTagName: function () { return createNodeList([]); },
      querySelector: function () { return null; },
      querySelectorAll: function () { return createNodeList([]); }
    };

    doc.implementation = {
      createHTMLDocument: function () {
        const d = makeDocument();
        d.contentType = 'text/html';
        return d;
      },
      createDocument: function (_ns, _qname) {
        const d = makeDocument();
        d.contentType = 'application/xml';
        return d;
      }
    };

    doc.documentElement = makeElement(doc, 'html', 'http://www.w3.org/1999/xhtml');
    doc.head = makeElement(doc, 'head', 'http://www.w3.org/1999/xhtml');
    doc.body = makeElement(doc, 'body', 'http://www.w3.org/1999/xhtml');
    doc.documentElement.appendChild(doc.head);
    doc.documentElement.appendChild(doc.body);
    doc.childNodes.push(doc.documentElement);
    return doc;
  }

  const document = makeDocument();
  const windowLike = {
    document: document,
    navigator: { userAgent: 'node-oracle' },
    Node: function Node() {},
    Element: function Element() {},
    HTMLElement: function HTMLElement() {},
    HTMLTemplateElement: function HTMLTemplateElement() {},
    DocumentFragment: function DocumentFragment() {},
    addEventListener: function () {},
    removeEventListener: function () {}
  };
  windowLike.window = windowLike;
  windowLike.self = windowLike;
  windowLike.top = windowLike;

  const DOMPurify = createDOMPurify(windowLike);
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('DOMPurify.sanitize unavailable');
  }

  let benignOut;
  try {
    benignOut = String(DOMPurify.sanitize('<p>hello</p>'));
  } catch (e) {
    evidence = 'benign operation threw: ' + (e && e.message ? e.message : String(e));
    finish();
    return;
  }

  if (!/hello/i.test(benignOut)) {
    evidence = 'benign output unexpected: ' + JSON.stringify(benignOut);
    finish();
    return;
  }

  operation_completed = true;

  const payload = '<svg><g/onload=alert(1)//<p>';
  try {
    const out = String(DOMPurify.sanitize(payload));
    const hasOnload = /onload\s*=\s*/i.test(out);
    const hasAlertLiteral = /alert\s*\(/i.test(out);
    exploit_succeeded = hasOnload || hasAlertLiteral;
    evidence = 'benign=' + JSON.stringify(benignOut) + ';malicious=' + JSON.stringify(out) + ';hasOnload=' + hasOnload + ';hasAlert=' + hasAlertLiteral;
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious call threw after benign success: ' + (e && e.message ? e.message : String(e));
  }

  finish();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/module error: ' + (e && e.message ? e.message : String(e));
  finish();
}
