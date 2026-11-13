let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');
  if (typeof createDOMPurify !== 'function') {
    throw new Error('dompurify export is not a function');
  }

  // DOMPurify on Node needs a window/document; provide a minimal deterministic fake DOM.
  function createFakeWindow() {
    function makeNode(nodeType, nodeName) {
      return {
        nodeType,
        nodeName,
        parentNode: null,
        childNodes: [],
        appendChild(child) {
          if (child) {
            child.parentNode = this;
            this.childNodes.push(child);
          }
          return child;
        },
        removeChild(child) {
          const i = this.childNodes.indexOf(child);
          if (i >= 0) this.childNodes.splice(i, 1);
          if (child) child.parentNode = null;
          return child;
        },
        insertBefore(child) {
          return this.appendChild(child);
        },
        cloneNode() {
          return makeNode(nodeType, nodeName);
        }
      };
    }

    function makeElement(tag) {
      const n = makeNode(1, String(tag || '').toUpperCase());
      n.tagName = n.nodeName;
      n.namespaceURI = 'http://www.w3.org/1999/xhtml';
      n.attributes = [];
      n.setAttribute = function (name, value) {
        const k = String(name);
        const v = String(value);
        const idx = this.attributes.findIndex((a) => a.name === k);
        if (idx >= 0) this.attributes[idx].value = v;
        else this.attributes.push({ name: k, value: v });
      };
      n.getAttribute = function (name) {
        const k = String(name);
        const hit = this.attributes.find((a) => a.name === k);
        return hit ? hit.value : null;
      };
      n.hasAttribute = function (name) {
        return this.attributes.some((a) => a.name === String(name));
      };
      n.removeAttribute = function (name) {
        const k = String(name);
        this.attributes = this.attributes.filter((a) => a.name !== k);
      };
      n.querySelectorAll = function () { return []; };
      n.getElementsByTagName = function () { return []; };
      Object.defineProperty(n, 'firstChild', { get() { return this.childNodes[0] || null; } });
      Object.defineProperty(n, 'nextSibling', { get() { return null; } });
      return n;
    }

    const doc = makeNode(9, '#document');
    doc.documentElement = makeElement('html');
    doc.head = makeElement('head');
    doc.body = makeElement('body');
    doc.documentElement.appendChild(doc.head);
    doc.documentElement.appendChild(doc.body);
    doc.readyState = 'complete';
    doc.createElement = (tag) => makeElement(tag);
    doc.createElementNS = (_ns, tag) => makeElement(tag);
    doc.createTextNode = (text) => ({ nodeType: 3, nodeName: '#text', data: String(text), textContent: String(text), parentNode: null });
    doc.createComment = (text) => ({ nodeType: 8, nodeName: '#comment', data: String(text), parentNode: null });
    doc.createDocumentFragment = () => makeNode(11, '#document-fragment');
    doc.importNode = (n) => n;
    doc.querySelectorAll = () => [];
    doc.getElementsByTagName = () => [];
    doc.addEventListener = () => {};
    doc.removeEventListener = () => {};
    doc.implementation = {
      createHTMLDocument: () => {
        const d = Object.assign({}, doc);
        d.documentElement = makeElement('html');
        d.head = makeElement('head');
        d.body = makeElement('body');
        d.documentElement.appendChild(d.head);
        d.documentElement.appendChild(d.body);
        return d;
      }
    };

    function DOMParser() {}
    DOMParser.prototype.parseFromString = function () {
      return doc.implementation.createHTMLDocument('');
    };

    return {
      document: doc,
      Node: function Node() {},
      Element: function Element() {},
      HTMLElement: function HTMLElement() {},
      DocumentFragment: function DocumentFragment() {},
      HTMLTemplateElement: function HTMLTemplateElement() {},
      SVGElement: function SVGElement() {},
      MathMLElement: function MathMLElement() {},
      DOMParser,
      addEventListener: () => {},
      removeEventListener: () => {}
    };
  }

  const windowLike = createFakeWindow();
  const DOMPurify = createDOMPurify(windowLike);
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('failed to initialize DOMPurify.sanitize');
  }

  // Benign operation first: must succeed before marking operation_completed.
  let benignOutput;
  try {
    benignOutput = String(DOMPurify.sanitize('plain safe text'));
  } catch (e) {
    evidence = 'benign sanitize threw: ' + (e && e.message ? e.message : String(e));
    finish();
    return;
  }

  if (benignOutput !== 'plain safe text') {
    evidence = 'benign sanitize unexpected output: ' + JSON.stringify(benignOutput);
    finish();
    return;
  }

  operation_completed = true;

  // Malicious payload representative of mXSS-style bypass class.
  const payload = '<math><annotation-xml encoding="text/html"><svg><script>alert(1)</script></svg></annotation-xml></math>';
  try {
    const out = String(DOMPurify.sanitize(payload));
    const hasScriptTag = /<script\b/i.test(out);
    exploit_succeeded = hasScriptTag;
    evidence = 'malicious_output=' + JSON.stringify(out) + ';hasScriptTag=' + hasScriptTag;
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