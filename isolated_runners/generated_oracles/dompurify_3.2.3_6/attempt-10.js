const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const createDOMPurify = require('dompurify');

  function makeNode(tagName, doc) {
    const upper = String(tagName || '').toUpperCase();
    const node = {
      nodeType: 1,
      nodeName: upper,
      tagName: upper,
      namespaceURI: 'http://www.w3.org/1999/xhtml',
      ownerDocument: doc,
      parentNode: null,
      childNodes: [],
      attributes: [],
      textContent: '',
      innerHTML: '',
      outerHTML: '',
      firstChild: null,
      firstElementChild: null,
      hasChildNodes() { return this.childNodes.length > 0; },
      appendChild(c) { if (c) { c.parentNode = this; this.childNodes.push(c); this.firstChild = this.childNodes[0] || null; this.firstElementChild = this.childNodes.find(n => n && n.nodeType === 1) || null; } return c; },
      insertBefore(c) { return this.appendChild(c); },
      removeChild(c) { const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); this.firstChild = this.childNodes[0] || null; this.firstElementChild = this.childNodes.find(n => n && n.nodeType === 1) || null; return c; },
      remove() { if (this.parentNode) this.parentNode.removeChild(this); },
      cloneNode() { const n = makeNode(this.tagName || 'div', this.ownerDocument); n.textContent = this.textContent; n.innerHTML = this.innerHTML; return n; },
      setAttribute(name, value) { this.attributes.push({ name: String(name), value: String(value), namespaceURI: null }); },
      setAttributeNS(ns, name, value) { this.attributes.push({ name: String(name), value: String(value), namespaceURI: ns || null }); },
      removeAttribute(name) { this.attributes = this.attributes.filter(a => a.name !== name); },
      getAttributeNode(name) { return this.attributes.find(a => a.name === name) || null; },
      hasAttribute(name) { return !!this.attributes.find(a => a.name === name); },
      getAttribute(name) { const a = this.attributes.find(x => x.name === name); return a ? a.value : null; }
    };
    if (upper === 'TEMPLATE') {
      node.content = { ownerDocument: doc };
    }
    return node;
  }

  const fakeDocument = {
    nodeType: 9,
    currentScript: null,
    createTextNode(text) { return { nodeType: 3, nodeName: '#text', textContent: String(text), ownerDocument: this, parentNode: null }; },
    createElement(tag) { return makeNode(tag, this); },
    createDocumentFragment() { return { nodeType: 11, ownerDocument: this, childNodes: [], appendChild() {}, firstChild: null }; },
    createNodeIterator() { return { nextNode() { return null; } }; },
    getElementsByTagName() { return [this.body]; },
    importNode(node) { return node; },
    implementation: {
      createHTMLDocument() {
        const d = Object.create(fakeDocument);
        d.body = makeNode('body', d);
        d.documentElement = d.body;
        return d;
      },
      createDocument() {
        const d = Object.create(fakeDocument);
        d.body = makeNode('template', d);
        d.documentElement = d.body;
        return d;
      }
    }
  };

  function Element() {}
  Element.prototype = makeNode('div', fakeDocument);

  const fakeWindow = {
    document: fakeDocument,
    Element,
    Node: function Node() {},
    DocumentFragment: function DocumentFragment() {},
    HTMLTemplateElement: function HTMLTemplateElement() {},
    NamedNodeMap: function NamedNodeMap() {},
    HTMLFormElement: function HTMLFormElement() {},
    NodeFilter: {
      SHOW_ELEMENT: 1,
      SHOW_COMMENT: 128,
      SHOW_TEXT: 4,
      SHOW_PROCESSING_INSTRUCTION: 64,
      SHOW_CDATA_SECTION: 8
    },
    DOMParser: function DOMParser() {
      this.parseFromString = function () {
        return fakeDocument.implementation.createHTMLDocument();
      };
    }
  };

  fakeDocument.body = makeNode('body', fakeDocument);
  fakeDocument.documentElement = fakeDocument.body;

  const DOMPurify = createDOMPurify(fakeWindow);
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') throw new Error('sanitize_missing');

  const benign = 'hello ${name} world';
  const benignOut = DOMPurify.sanitize(benign, { SAFE_FOR_TEMPLATES: false });
  if (typeof benignOut !== 'string' || benignOut.indexOf('${') === -1) throw new Error('benign_behavior_unexpected');

  result.operation_completed = true;

  const malicious = 'prefix ${ATTACK_UNCLOSED';
  try {
    const malOut = DOMPurify.sanitize(malicious, { SAFE_FOR_TEMPLATES: true });
    const leaked = typeof malOut === 'string' && malOut.indexOf('${') !== -1;
    result.exploit_succeeded = leaked;
    result.evidence = JSON.stringify({ benignOut, malOut, leaked });
  } catch (e) {
    result.exploit_succeeded = false;
    result.evidence = 'malicious_rejected';
  }
} catch (e) {
  result.operation_completed = false;
  result.exploit_succeeded = false;
  result.evidence = 'setup_or_benign_error:' + (e && e.message ? e.message : String(e));
}

out();