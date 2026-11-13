'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function buildFakeWindow() {
  // A minimal, self-contained DOM implementation (no external deps) that is
  // sufficient for DOMPurify's core sanitize() algorithm to run end-to-end,
  // including basic HTML parsing via a tiny recursive-descent parser.

  const NODE_TYPES = {
    ELEMENT_NODE: 1,
    TEXT_NODE: 3,
    COMMENT_NODE: 8,
    DOCUMENT_FRAGMENT_NODE: 11,
  };

  class FakeNode {
    constructor(nodeType) {
      this.nodeType = nodeType;
      this.childNodes = [];
      this.parentNode = null;
      this._ownerDocument = null;
    }
    get firstChild() { return this.childNodes[0] || null; }
    get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
    get nextSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return this.parentNode.childNodes[idx + 1] || null;
    }
    get previousSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return this.parentNode.childNodes[idx - 1] || null;
    }
    appendChild(child) {
      if (child.parentNode) child.parentNode.removeChild(child);
      child.parentNode = this;
      this.childNodes.push(child);
      return child;
    }
    insertBefore(child, ref) {
      if (child.parentNode) child.parentNode.removeChild(child);
      child.parentNode = this;
      if (ref == null) { this.childNodes.push(child); return child; }
      const idx = this.childNodes.indexOf(ref);
      if (idx === -1) { this.childNodes.push(child); }
      else { this.childNodes.splice(idx, 0, child); }
      return child;
    }
    removeChild(child) {
      const idx = this.childNodes.indexOf(child);
      if (idx >= 0) this.childNodes.splice(idx, 1);
      child.parentNode = null;
      return child;
    }
    replaceChild(nw, old) {
      const idx = this.childNodes.indexOf(old);
      if (idx >= 0) { this.childNodes[idx] = nw; nw.parentNode = this; old.parentNode = null; }
      return old;
    }
    cloneNode(deep) {
      const clone = Object.create(Object.getPrototypeOf(this));
      Object.assign(clone, this);
      clone.childNodes = [];
      clone.parentNode = null;
      if (this.attributes) clone.attributes = this.attributes.map(a => ({ name: a.name, value: a.value, namespaceURI: a.namespaceURI || null }));
      if (deep) {
        for (const c of this.childNodes) clone.appendChild(c.cloneNode(true));
      }
      return clone;
    }
  }

  class FakeText extends FakeNode {
    constructor(data) {
      super(NODE_TYPES.TEXT_NODE);
      this.data = String(data == null ? '' : data);
      this.nodeName = '#text';
    }
    get textContent() { return this.data; }
    set textContent(v) { this.data = String(v); }
  }

  class FakeComment extends FakeNode {
    constructor(data) {
      super(NODE_TYPES.COMMENT_NODE);
      this.data = String(data == null ? '' : data);
      this.nodeName = '#comment';
    }
    get textContent() { return this.data; }
    set textContent(v) { this.data = String(v); }
  }

  class FakeElement extends FakeNode {
    constructor(tagName) {
      super(NODE_TYPES.ELEMENT_NODE);
      this.tagName = String(tagName).toUpperCase();
      this.nodeName = this.tagName;
      this.attributes = [];
      this._attrMap = Object.create(null);
      this.namespaceURI = 'http://www.w3.org/1999/xhtml';
      this._content = null; // template content fragment
    }
    get content() {
      if (this.tagName === 'TEMPLATE') {
        if (!this._content) {
          this._content = new FakeDocumentFragment();
          this._content._ownerDocument = this._ownerDocument;
          for (const c of this.childNodes.slice()) {
            this._content.appendChild(c);
          }
        }
        return this._content;
      }
      return undefined;
    }
    setAttribute(name, value) {
      const key = String(name);
      if (!(key in this._attrMap)) this.attributes.push({ name: key, value: String(value), namespaceURI: null });
      else { const a = this.attributes.find(a => a.name === key); if (a) a.value = String(value); }
      this._attrMap[key] = String(value);
    }
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this._attrMap, name) ? this._attrMap[name] : null;
    }
    hasAttribute(name) { return Object.prototype.hasOwnProperty.call(this._attrMap, name); }
    removeAttribute(name) {
      delete this._attrMap[name];
      this.attributes = this.attributes.filter(a => a.name !== name);
    }
    getAttributeNode(name) {
      if (!this.hasAttribute(name)) return null;
      return { name, value: this._attrMap[name], namespaceURI: null };
    }
    get outerHTML() { return serialize(this); }
    get innerHTML() { return this.childNodes.map(serialize).join(''); }
    set innerHTML(html) {
      this.childNodes = [];
      const frag = parseHTML(html, this._ownerDocument);
      for (const c of frag.childNodes.slice()) this.appendChild(c);
    }
    get textContent() {
      let s = '';
      for (const c of this.childNodes) s += c.textContent;
      return s;
    }
    set textContent(v) {
      this.childNodes = [];
      this.appendChild(new FakeText(v));
    }
  }

  class FakeDocumentFragment extends FakeNode {
    constructor() {
      super(NODE_TYPES.DOCUMENT_FRAGMENT_NODE);
      this.nodeName = '#document-fragment';
    }
    get textContent() {
      let s = '';
      for (const c of this.childNodes) s += c.textContent;
      return s;
    }
  }

  const VOID_TAGS = new Set(['area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr']);

  function escapeText(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function escapeAttr(s) {
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
  }

  function serialize(node) {
    if (node.nodeType === NODE_TYPES.TEXT_NODE) return escapeText(node.data);
    if (node.nodeType === NODE_TYPES.COMMENT_NODE) return '<!--' + node.data + '-->';
    if (node.nodeType === NODE_TYPES.DOCUMENT_FRAGMENT_NODE) return node.childNodes.map(serialize).join('');
    if (node.nodeType === NODE_TYPES.ELEMENT_NODE) {
      const tag = node.tagName.toLowerCase();
      let attrs = node.attributes.map(a => ` ${a.name}="${escapeAttr(a.value)}"`).join('');
      if (VOID_TAGS.has(tag)) return `<${tag}${attrs}>`;
      let inner;
      if (tag === 'template') {
        inner = (node.content ? node.content.childNodes : node.childNodes).map(serialize).join('');
      } else {
        inner = node.childNodes.map(serialize).join('');
      }
      return `<${tag}${attrs}>${inner}</${tag}>`;
    }
    return '';
  }

  // Extremely small HTML tokenizer/parser sufficient for basic tag/attr/text/comment structures.
  function parseHTML(html, ownerDocument) {
    const root = new FakeDocumentFragment();
    root._ownerDocument = ownerDocument;
    const stack = [root];
    let i = 0;
    const n = html.length;
    function top() { return stack[stack.length - 1]; }
    while (i < n) {
      if (html.startsWith('<!--', i)) {
        const end = html.indexOf('-->', i + 4);
        const endIdx = end === -1 ? n : end;
        const data = html.slice(i + 4, endIdx);
        const c = new FakeComment(data);
        c._ownerDocument = ownerDocument;
        top().appendChild(c);
        i = end === -1 ? n : end + 3;
        continue;
      }
      if (html[i] === '<') {
        if (html[i + 1] === '/') {
          const end = html.indexOf('>', i);
          const endIdx = end === -1 ? n : end;
          const name = html.slice(i + 2, endIdx).trim().toLowerCase();
          for (let j = stack.length - 1; j >= 1; j--) {
            if (stack[j].tagName && stack[j].tagName.toLowerCase() === name) {
              stack.length = j;
              break;
            }
          }
          i = end === -1 ? n : end + 1;
          continue;
        }
        const tagMatch = /^<([a-zA-Z][a-zA-Z0-9:-]*)/.exec(html.slice(i));
        if (tagMatch) {
          let j = i + tagMatch[0].length;
          const el = new FakeElement(tagMatch[1]);
          el._ownerDocument = ownerDocument;
          // parse attributes until '>' not inside quotes
          let attrBuf = '';
          let selfClose = false;
          while (j < n && html[j] !== '>') {
            attrBuf += html[j];
            j++;
          }
          if (attrBuf.trim().endsWith('/')) { selfClose = true; attrBuf = attrBuf.replace(/\/\s*$/, ''); }
          const attrRe = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*("([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
          let m;
          while ((m = attrRe.exec(attrBuf))) {
            const name = m[1];
            if (!name) continue;
            const value = m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : m[5] !== undefined ? m[5] : '';
            el.setAttribute(name, value);
          }
          top().appendChild(el);
          i = j + 1;
          const tagLower = tagMatch[1].toLowerCase();
          if (!VOID_TAGS.has(tagLower) && !selfClose) {
            stack.push(el);
          }
          continue;
        }
      }
      let next = html.indexOf('<', i);
      if (next === -1) next = n;
      const text = html.slice(i, next);
      if (text.length > 0) {
        const t = new FakeText(text.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"'));
        t._ownerDocument = ownerDocument;
        top().appendChild(t);
      }
      i = next;
    }
    return root;
  }

  function makeDocument() {
    const doc = new FakeElement('#document');
    doc.nodeType = 9; // DOCUMENT_NODE
    doc.nodeName = '#document';
    const html = new FakeElement('html');
    const body = new FakeElement('body');
    const head = new FakeElement('head');
    html.appendChild(head);
    html.appendChild(body);
    doc.appendChild(html);
    doc.body = body;
    doc.documentElement = html;
    doc._ownerDocument = doc;
    html._ownerDocument = doc;
    body._ownerDocument = doc;
    head._ownerDocument = doc;

    doc.createElement = (tag) => { const e = new FakeElement(tag); e._ownerDocument = doc; return e; };
    doc.createTextNode = (data) => { const t = new FakeText(data); t._ownerDocument = doc; return t; };
    doc.createComment = (data) => { const c = new FakeComment(data); c._ownerDocument = doc; return c; };
    doc.createDocumentFragment = () => { const f = new FakeDocumentFragment(); f._ownerDocument = doc; return f; };
    doc.implementation = {
      createHTMLDocument(title) {
        return makeDocument();
      },
      hasFeature() { return false; },
    };
    doc.createNodeIterator = (root, whatToShow, filter) => {
      const nodes = [];
      (function walk(node) {
        for (const c of node.childNodes.slice()) {
          nodes.push(c);
          walk(c);
        }
      })(root);
      let idx = 0;
      return {
        nextNode() {
          while (idx < nodes.length) {
            const n = nodes[idx++];
            if (n && n.parentNode !== undefined) return n;
          }
          return null;
        },
      };
    };
    doc.getElementsByTagName = (tag) => {
      const out = [];
      (function walk(node) {
        for (const c of node.childNodes) {
          if (c.nodeType === NODE_TYPES.ELEMENT_NODE && (tag === '*' || c.tagName.toLowerCase() === tag.toLowerCase())) out.push(c);
          walk(c);
        }
      })(doc);
      return out;
    };
    doc.querySelectorAll = () => [];
    doc.querySelector = () => null;
    doc.cloneNode = () => makeDocument();
    doc.contains = () => true;
    return doc;
  }

  const document = makeDocument();

  // Patch body.innerHTML setter to use our parser bound to this document.
  Object.defineProperty(FakeElement.prototype, 'innerHTML', {
    get() {
      if (this.tagName === 'TEMPLATE') {
        return (this.content ? this.content.childNodes : this.childNodes).map(serialize).join('');
      }
      return this.childNodes.map(serialize).join('');
    },
    set(html) {
      this.childNodes = [];
      this._content = null;
      const frag = parseHTML(html, this._ownerDocument || document);
      if (this.tagName === 'TEMPLATE') {
        const c = this.content;
        for (const n of frag.childNodes.slice()) c.appendChild(n);
      } else {
        for (const n of frag.childNodes.slice()) this.appendChild(n);
      }
    },
    configurable: true,
  });

  const NodeFilter = { SHOW_ELEMENT: 1, SHOW_TEXT: 4, SHOW_COMMENT: 128, SHOW_ALL: -1, FILTER_ACCEPT: 1, FILTER_REJECT: 2, FILTER_SKIP: 3 };

  function DOMParserCtor() {}
  DOMParserCtor.prototype.parseFromString = function (markup) {
    const doc = makeDocument();
    doc.body.innerHTML = markup;
    return doc;
  };

  const win = {
    document,
    Node: NODE_TYPES,
    NodeFilter,
    HTMLTemplateElement: FakeElement,
    DocumentFragment: FakeDocumentFragment,
    Element: FakeElement,
    NamedNodeMap: Array,
    DOMParser: DOMParserCtor,
    location: { href: 'https://example.org/' },
    navigator: { userAgent: 'node-fake-dom' },
  };
  win.window = win;
  return win;
}

function main() {
  let createDOMPurify;
  try {
    createDOMPurify = require('dompurify');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to require dompurify: ' + String(e && e.message) });
    return;
  }

  const marker = 'DP_ORACLE_' + process.pid + '_' + Date.now();

  let tmpDir;
  try {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dompurify-oracle-'));
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to create tmp dir: ' + String(e && e.message) });
    return;
  }

  let DOMPurify;
  try {
    const fakeWindow = buildFakeWindow();
    DOMPurify = createDOMPurify(fakeWindow);
    if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'DOMPurify instance missing sanitize function after construction' });
      return;
    }
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to construct DOMPurify instance with fake DOM: ' + String(e && e.message) });
    return;
  }

  // --- Benign operation first ---
  let benignOutput;
  try {
    const benignInput = '<p>Hello <b>world</b></p> ' + marker;
    benignOutput = DOMPurify.sanitize(benignInput);
    if (typeof benignOutput !== 'string' || !benignOutput.includes('Hello') || !benignOutput.includes('world') || !benignOutput.includes(marker)) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign sanitize call did not produce expected output: ' + String(benignOutput) });
      return;
    }
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign sanitize call threw: ' + String(e && e.message) });
    return;
  }

  const operation_completed = true;

  // --- Malicious operation: nested-template mXSS payload ---
  let maliciousOutput;
  try {
    const payload = '<svg><template><template><style></template><img src=x onerror="window.__DP_PWNED_' + marker + '__=1"></style></template></svg>';
    maliciousOutput = DOMPurify.sanitize(payload);
  } catch (e) {
    finish({ operation_completed, exploit_succeeded: false, evidence: 'Malicious sanitize call threw (treated as blocked): ' + String(e && e.message) });
    return;
  }

  let exploit_succeeded = false;
  let evidence = '';

  try {
    const rawHasOnerror = /onerror\s*=/i.test(maliciousOutput);
    const rawHasPwnedMarker = maliciousOutput.includes('__DP_PWNED_' + marker + '__');

    if (rawHasOnerror || rawHasPwnedMarker) {
      exploit_succeeded = true;
      evidence = 'Sanitized output retained an onerror handler / executable construct after mXSS payload: ' +
        JSON.stringify(maliciousOutput).slice(0, 500);
    } else {
      evidence = 'Sanitized output contained no onerror attribute or script-triggering construct: ' +
        JSON.stringify(maliciousOutput).slice(0, 500);
    }
  } catch (e) {
    evidence = 'Verification step threw while inspecting sanitized output (treated as blocked): ' + String(e && e.message);
    exploit_succeeded = false;
  }

  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (e) {
    // ignore cleanup errors
  }

  finish({ operation_completed, exploit_succeeded, evidence });
}

try {
  main();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed: false, exploit_succeeded: false, evidence: 'Uncaught top-level exception: ' + String(e && e.message) }));
}
