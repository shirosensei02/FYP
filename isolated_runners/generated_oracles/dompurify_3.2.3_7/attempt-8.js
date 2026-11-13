let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');

  function makeElement(name, ownerDocument) {
    const el = {
      nodeType: 1,
      nodeName: String(name || 'div').toUpperCase(),
      namespaceURI: 'http://www.w3.org/1999/xhtml',
      attributes: [],
      childNodes: [],
      parentNode: null,
      ownerDocument: ownerDocument || null,
      _innerHTML: '',
      setAttribute: function (k, v) {
        const key = String(k);
        const val = String(v);
        const i = this.attributes.findIndex(function (a) { return a.name === key; });
        if (i >= 0) this.attributes[i].value = val;
        else this.attributes.push({ name: key, value: val });
      },
      getAttribute: function (k) {
        const key = String(k);
        const a = this.attributes.find(function (x) { return x.name === key; });
        return a ? a.value : null;
      },
      hasAttribute: function (k) {
        return this.getAttribute(k) !== null;
      },
      removeAttribute: function (k) {
        const key = String(k);
        this.attributes = this.attributes.filter(function (a) { return a.name !== key; });
      },
      appendChild: function (n) {
        if (n && typeof n === 'object') n.parentNode = this;
        this.childNodes.push(n);
        return n;
      },
      removeChild: function (n) {
        const i = this.childNodes.indexOf(n);
        if (i >= 0) this.childNodes.splice(i, 1);
        return n;
      },
      insertBefore: function (n) {
        return this.appendChild(n);
      },
      cloneNode: function () { return makeElement(this.nodeName, this.ownerDocument); },
      querySelectorAll: function () { return []; },
      getElementsByTagName: function () { return []; }
    };

    Object.defineProperty(el, 'innerHTML', {
      get: function () { return this._innerHTML; },
      set: function (v) { this._innerHTML = String(v); }
    });

    return el;
  }

  const fakeDocument = {
    nodeType: 9,
    createElement: function (name) { return makeElement(name, fakeDocument); },
    createElementNS: function (ns, name) {
      const el = makeElement(name, fakeDocument);
      el.namespaceURI = String(ns || '');
      return el;
    },
    createTextNode: function (t) { return { nodeType: 3, data: String(t || ''), parentNode: null, ownerDocument: fakeDocument }; },
    createComment: function (t) { return { nodeType: 8, data: String(t || ''), parentNode: null, ownerDocument: fakeDocument }; },
    createDocumentFragment: function () {
      return {
        nodeType: 11,
        childNodes: [],
        ownerDocument: fakeDocument,
        appendChild: function (n) { this.childNodes.push(n); return n; },
        removeChild: function (n) { const i = this.childNodes.indexOf(n); if (i >= 0) this.childNodes.splice(i, 1); return n; }
      };
    },
    getElementsByTagName: function () { return []; },
    querySelectorAll: function () { return []; },
    implementation: {
      createHTMLDocument: function () {
        const d = {
          nodeType: 9,
          createElement: fakeDocument.createElement,
          createElementNS: fakeDocument.createElementNS,
          createTextNode: fakeDocument.createTextNode,
          createComment: fakeDocument.createComment,
          createDocumentFragment: fakeDocument.createDocumentFragment,
          getElementsByTagName: fakeDocument.getElementsByTagName,
          querySelectorAll: fakeDocument.querySelectorAll,
          implementation: null,
          documentElement: null,
          body: null
        };
        d.implementation = { createHTMLDocument: function () { return d; } };
        d.documentElement = makeElement('html', d);
        d.body = makeElement('body', d);
        return d;
      },
      createDocument: function () {
        return this.createHTMLDocument('');
      }
    },
    documentElement: null,
    body: null
  };

  fakeDocument.documentElement = makeElement('html', fakeDocument);
  fakeDocument.body = makeElement('body', fakeDocument);

  const windowLike = {
    window: null,
    self: null,
    top: null,
    document: fakeDocument,
    navigator: { userAgent: 'node' },
    Node: function Node() {},
    Element: function Element() {},
    HTMLElement: function HTMLElement() {},
    HTMLTemplateElement: function HTMLTemplateElement() {},
    DocumentFragment: function DocumentFragment() {}
  };
  windowLike.window = windowLike;
  windowLike.self = windowLike;
  windowLike.top = windowLike;

  const DOMPurify = createDOMPurify(windowLike);

  let benignOut;
  try {
    benignOut = DOMPurify.sanitize('<p>Hello</p>');
  } catch (e) {
    throw new Error('benign sanitize failed: ' + (e && e.message ? e.message : String(e)));
  }

  if (typeof benignOut !== 'string' || benignOut.toLowerCase().indexOf('hello') === -1) {
    throw new Error('benign sanitize failed: unexpected output: ' + String(benignOut));
  }

  operation_completed = true;

  const maliciousInput = '<svg><g/onload=alert(1)></g></svg>';
  let maliciousOut;
  try {
    maliciousOut = DOMPurify.sanitize(maliciousInput, {
      USE_PROFILES: { svg: true, svgFilters: true, html: false }
    });
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (err && err.message ? err.message : String(err));
    emit();
    return;
  }

  const out = String(maliciousOut);
  const hasHandler = /\son[a-z0-9_-]+\s*=\s*/i.test(out);
  exploit_succeeded = hasHandler;
  evidence = JSON.stringify({ benignOut: String(benignOut), maliciousOut: out, hasHandler: hasHandler });
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

emit();