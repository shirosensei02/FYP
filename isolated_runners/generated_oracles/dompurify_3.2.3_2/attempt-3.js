'use strict';
const marker = 'dompurify_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);

function buildMiniDom() {
  const NODE_TYPE = {ELEMENT:1, TEXT:3, COMMENT:8, DOCUMENT:9, FRAGMENT:11};
  class EventTarget { addEventListener(){} removeEventListener(){} }
  class Node extends EventTarget {
    constructor(nodeType, nodeName) {
      super();
      this.nodeType = nodeType;
      this.nodeName = nodeName;
      this.childNodes = [];
      this.parentNode = null;
      this.ownerDocument = null;
    }
    get firstChild() { return this.childNodes[0] || null; }
    get firstElementChild() {
      for (const c of this.childNodes) if (c.nodeType === NODE_TYPE.ELEMENT) return c;
      return null;
    }
    get lastChild() { return this.childNodes[this.childNodes.length-1] || null; }
    hasChildNodes() { return this.childNodes.length > 0; }
    appendChild(child) {
      if (child.nodeType === NODE_TYPE.FRAGMENT) {
        const kids = child.childNodes.slice();
        for (const k of kids) this.appendChild(k);
        return child;
      }
      if (child.parentNode) child.parentNode.removeChild(child);
      child.parentNode = this;
      child.ownerDocument = this.ownerDocument;
      this.childNodes.push(child);
      return child;
    }
    insertBefore(newNode, refNode) {
      if (newNode.nodeType === NODE_TYPE.FRAGMENT) {
        const kids = newNode.childNodes.slice();
        for (const k of kids) this.insertBefore(k, refNode);
        return newNode;
      }
      if (newNode.parentNode) newNode.parentNode.removeChild(newNode);
      newNode.parentNode = this;
      newNode.ownerDocument = this.ownerDocument;
      if (refNode == null) { this.childNodes.push(newNode); return newNode; }
      const idx = this.childNodes.indexOf(refNode);
      if (idx === -1) this.childNodes.push(newNode);
      else this.childNodes.splice(idx, 0, newNode);
      return newNode;
    }
    removeChild(child) {
      const idx = this.childNodes.indexOf(child);
      if (idx !== -1) this.childNodes.splice(idx, 1);
      child.parentNode = null;
      return child;
    }
    remove() { if (this.parentNode) this.parentNode.removeChild(this); }
    get nextSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return this.parentNode.childNodes[idx+1] || null;
    }
    cloneNode(deep) {
      const clone = cloneNodeImpl(this, deep);
      return clone;
    }
  }
  function cloneNodeImpl(node, deep) {
    let clone;
    if (node.nodeType === NODE_TYPE.TEXT) {
      clone = new TextNode(node.data);
    } else if (node.nodeType === NODE_TYPE.COMMENT) {
      clone = new CommentNode(node.data);
    } else if (node.nodeType === NODE_TYPE.ELEMENT) {
      clone = new Element(node.tagName);
      for (const attr of node._attrs) clone.setAttribute(attr.name, attr.value);
    } else {
      clone = new DocumentFragment();
    }
    clone.ownerDocument = node.ownerDocument;
    if (deep) {
      for (const child of node.childNodes) {
        clone.appendChild(cloneNodeImpl(child, true));
      }
    }
    return clone;
  }
  class TextNode extends Node {
    constructor(data) {
      super(NODE_TYPE.TEXT, '#text');
      this.data = data || '';
    }
    get textContent() { return this.data; }
    set textContent(v) { this.data = v; }
    get nodeValue() { return this.data; }
    set nodeValue(v) { this.data = v; }
  }
  class CommentNode extends Node {
    constructor(data) {
      super(NODE_TYPE.COMMENT, '#comment');
      this.data = data || '';
    }
    get textContent() { return this.data; }
    set textContent(v) { this.data = v; }
  }
  class Attr {
    constructor(name, value, namespaceURI) {
      this.name = name;
      this.value = value;
      this.namespaceURI = namespaceURI || null;
    }
  }
  class NamedNodeMap {
    constructor(owner) { this._owner = owner; }
    get length() { return this._owner._attrs.length; }
    item(i) { return this._owner._attrs[i]; }
  }
  class Element extends Node {
    constructor(tagName, namespaceURI) {
      super(NODE_TYPE.ELEMENT, tagName.toUpperCase());
      this.tagName = tagName.toUpperCase();
      this._localName = tagName.toLowerCase();
      this.namespaceURI = namespaceURI || 'http://www.w3.org/1999/xhtml';
      this._attrs = [];
      this.attributes = new NamedNodeMap(this);
    }
    get localName() { return this._localName; }
    setAttribute(name, value) {
      const existing = this._attrs.find(a => a.name === name);
      if (existing) existing.value = String(value);
      else this._attrs.push(new Attr(name, String(value)));
    }
    setAttributeNS(ns, name, value) {
      const existing = this._attrs.find(a => a.name === name);
      if (existing) { existing.value = String(value); existing.namespaceURI = ns; }
      else this._attrs.push(new Attr(name, String(value), ns));
    }
    getAttribute(name) {
      const a = this._attrs.find(x => x.name === name);
      return a ? a.value : null;
    }
    getAttributeNode(name) {
      return this._attrs.find(x => x.name === name) || null;
    }
    hasAttribute(name) { return !!this._attrs.find(x => x.name === name); }
    removeAttribute(name) {
      const idx = this._attrs.findIndex(x => x.name === name);
      if (idx !== -1) this._attrs.splice(idx, 1);
    }
    get innerHTML() { return serializeChildren(this); }
    set innerHTML(html) {
      this.childNodes = [];
      parseFragmentInto(this, html);
    }
    get outerHTML() { return serializeNode(this); }
    get textContent() {
      let s = '';
      for (const c of this.childNodes) {
        if (c.nodeType === NODE_TYPE.TEXT) s += c.data;
        else if (c.nodeType === NODE_TYPE.ELEMENT) s += c.textContent;
      }
      return s;
    }
    set textContent(v) {
      this.childNodes = [];
      if (v) this.appendChild(new TextNode(v));
    }
  }
  class DocumentFragment extends Node {
    constructor() { super(NODE_TYPE.FRAGMENT, '#document-fragment'); }
  }
  class HTMLFormElement extends Element {}
  class HTMLTemplateElement extends Element {
    constructor() {
      super('template');
      this.content = new DocumentFragment();
      this.content.ownerDocument = null;
    }
  }

  function escapeText(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
  function serializeAttrs(el) {
    return el._attrs.map(a => ' ' + a.name + '="' + String(a.value).replace(/"/g,'&quot;') + '"').join('');
  }
  function serializeChildren(node) {
    let s = '';
    for (const c of node.childNodes) s += serializeNode(c);
    return s;
  }
  function serializeNode(node) {
    if (node.nodeType === NODE_TYPE.TEXT) return escapeText(node.data);
    if (node.nodeType === NODE_TYPE.COMMENT) return '<!--' + node.data + '-->';
    if (node.nodeType === NODE_TYPE.ELEMENT) {
      const tag = node._localName;
      const voidEls = {img:1, br:1, hr:1, input:1, area:1, base:1, col:1, embed:1, link:1, meta:1, param:1, source:1, track:1, wbr:1};
      if (voidEls[tag]) return '<' + tag + serializeAttrs(node) + '>';
      return '<' + tag + serializeAttrs(node) + '>' + serializeChildren(node) + '</' + tag + '>';
    }
    if (node.nodeType === NODE_TYPE.FRAGMENT) return serializeChildren(node);
    return '';
  }

  // Extremely small HTML tokenizer/parser - enough for flat/simple nested tags used in test.
  function parseFragmentInto(parent, html) {
    const doc = parent.ownerDocument;
    let i = 0;
    const stack = [parent];
    const len = html.length;
    while (i < len) {
      const lt = html.indexOf('<', i);
      if (lt === -1) {
        const text = html.slice(i);
        if (text) stack[stack.length-1].appendChild(makeText(doc, text));
        break;
      }
      if (lt > i) {
        const text = html.slice(i, lt);
        if (text) stack[stack.length-1].appendChild(makeText(doc, text));
      }
      if (html.startsWith('<!--', lt)) {
        const end = html.indexOf('-->', lt+4);
        const endIdx = end === -1 ? len : end+3;
        const data = html.slice(lt+4, end === -1 ? len : end);
        stack[stack.length-1].appendChild(makeComment(doc, data));
        i = endIdx;
        continue;
      }
      const gt = html.indexOf('>', lt);
      if (gt === -1) { i = len; break; }
      const tagContent = html.slice(lt+1, gt);
      i = gt + 1;
      if (tagContent.startsWith('/')) {
        const name = tagContent.slice(1).trim().toLowerCase();
        for (let k = stack.length - 1; k >= 1; k--) {
          if (stack[k]._localName === name) {
            stack.length = k;
            break;
          }
        }
        continue;
      }
      const selfClose = /\/\s*$/.test(tagContent);
      let body = selfClose ? tagContent.replace(/\/\s*$/, '') : tagContent;
      const m = body.match(/^([a-zA-Z0-9\-:]+)/);
      if (!m) continue;
      const name = m[1].toLowerCase();
      const rest = body.slice(m[0].length);
      const el = makeElement(doc, name);
      const attrRe = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*("([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
      let am;
      while ((am = attrRe.exec(rest)) !== null) {
        if (!am[1]) continue;
        const attrName = am[1];
        const attrValue = am[3] !== undefined ? am[3] : (am[4] !== undefined ? am[4] : (am[5] !== undefined ? am[5] : ''));
        el.setAttribute(attrName, attrValue);
      }
      stack[stack.length-1].appendChild(el);
      const voidEls = {img:1, br:1, hr:1, input:1, area:1, base:1, col:1, embed:1, link:1, meta:1, param:1, source:1, track:1, wbr:1};
      if (!selfClose && !voidEls[name]) {
        stack.push(el);
      }
    }
  }
  function makeText(doc, data) { const t = new TextNode(data); t.ownerDocument = doc; return t; }
  function makeComment(doc, data) { const c = new CommentNode(data); c.ownerDocument = doc; return c; }
  function makeElement(doc, name) { const e = new Element(name); e.ownerDocument = doc; return e; }

  class NodeIterator {
    constructor(root) {
      this._queue = [];
      this._collect(root);
      this._idx = 0;
    }
    _collect(node) {
      for (const c of node.childNodes.slice()) {
        this._queue.push(c);
        this._collect(c);
      }
    }
    nextNode() {
      if (this._idx >= this._queue.length) return null;
      return this._queue[this._idx++];
    }
  }

  class Document extends Node {
    constructor() {
      super(NODE_TYPE.DOCUMENT, '#document');
      this.ownerDocument = null;
      this.documentElement = null;
      this.doctype = null;
      this.currentScript = null;
      this.implementation = {
        createHTMLDocument: () => {
          const d = new Document();
          const html = makeElement(d, 'html');
          const head = makeElement(d, 'head');
          const body = makeElement(d, 'body');
          html.appendChild(head);
          html.appendChild(body);
          d.appendChild(html);
          d.documentElement = html;
          return d;
        },
        createDocument: (ns, qname) => {
          const d = new Document();
          const root = makeElement(d, qname || 'root');
          d.appendChild(root);
          d.documentElement = root;
          return d;
        }
      };
    }
    createElement(name) { return makeElement(this, name); }
    createElementNS(ns, name) { const e = makeElement(this, name); e.namespaceURI = ns; return e; }
    createTextNode(data) { return makeText(this, data); }
    createComment(data) { return makeComment(this, data); }
    createDocumentFragment() { const f = new DocumentFragment(); f.ownerDocument = this; return f; }
    createNodeIterator(root) { return new NodeIterator(root); }
    getElementsByTagName(tag) {
      const results = [];
      const walk = (node) => {
        for (const c of node.childNodes) {
          if (c.nodeType === NODE_TYPE.ELEMENT && (tag === '*' || c._localName === tag)) results.push(c);
          walk(c);
        }
      };
      walk(this);
      return results;
    }
    importNode(node, deep) { return cloneNodeImpl(node, deep); }
    get body() {
      const found = this.getElementsByTagName('body');
      return found[0] || null;
    }
  }

  class DOMParser {
    parseFromString(markup, type) {
      const doc = new Document();
      const html = makeElement(doc, 'html');
      const head = makeElement(doc, 'head');
      const body = makeElement(doc, 'body');
      html.appendChild(head);
      html.appendChild(body);
      doc.appendChild(html);
      doc.documentElement = html;
      const bodyMatch = markup.match(/<body[^>]*>([\s\S]*)<\/body>/i);
      const innerHtml = bodyMatch ? bodyMatch[1] : markup;
      parseFragmentInto(body, innerHtml);
      return doc;
    }
  }

  const NodeFilter = {
    SHOW_ELEMENT: 1, SHOW_COMMENT: 128, SHOW_TEXT: 4, SHOW_PROCESSING_INSTRUCTION: 64, SHOW_CDATA_SECTION: 8
  };

  const document = new Document();
  const htmlEl = makeElement(document, 'html');
  const headEl = makeElement(document, 'head');
  const bodyEl = makeElement(document, 'body');
  htmlEl.appendChild(headEl);
  htmlEl.appendChild(bodyEl);
  document.appendChild(htmlEl);
  document.documentElement = htmlEl;

  const window = {
    document,
    DocumentFragment,
    HTMLTemplateElement,
    Node,
    Element,
    NodeFilter,
    NamedNodeMap,
    MozNamedAttrMap: NamedNodeMap,
    HTMLFormElement,
    DOMParser,
    trustedTypes: undefined,
    Reflect: typeof Reflect !== 'undefined' ? Reflect : undefined
  };
  return window;
}

function run() {
  let createDOMPurify;
  try {
    createDOMPurify = require('dompurify');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:false, exploit_succeeded:false, evidence:'module resolution failed: ' + String(e && e.message)}));
    return;
  }

  let window;
  try {
    window = buildMiniDom();
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:false, exploit_succeeded:false, evidence:'mini-dom setup failed: ' + String(e && e.message)}));
    return;
  }

  let DOMPurify;
  try {
    DOMPurify = createDOMPurify(window);
    if (!DOMPurify || DOMPurify.isSupported === false) {
      throw new Error('DOMPurify reports isSupported=false with fixture window');
    }
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:false, exploit_succeeded:false, evidence:'DOMPurify init failed: ' + String(e && e.message)}));
    return;
  }

  // Benign operation first: sanitize a simple safe snippet with SAFE_FOR_TEMPLATES true.
  const marker = 'dompurify_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  let benignOutput;
  try {
    benignOutput = DOMPurify.sanitize('<b>' + marker + ' benign</b>', { SAFE_FOR_TEMPLATES: true });
    if (typeof benignOutput !== 'string' || benignOutput.indexOf('benign') === -1) {
      throw new Error('benign sanitize did not return expected content: ' + String(benignOutput));
    }
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:false, exploit_succeeded:false, evidence:'benign sanitize call failed: ' + String(e && e.message)}));
    return;
  }

  const operation_completed = true;

  // Malicious input exploiting the incorrect TMPLIT_EXPR regex (/\$\{[\w\W]*/gm instead of
  // /\$\{[\w\W]*}/gm) under SAFE_FOR_TEMPLATES:true. The unterminated template-literal
  // detector over-matches from a '${' onward to end-of-string across a text node that
  // DOMPurify then neutralizes, but due to the bug an unrelated '${' sequence placed
  // before a dangerous payload causes the greedy template-expr stripping to consume
  // content in a way that allows a crafted payload to survive mutation across nodes.
  // We use an input with a stray '${' followed by dangerous markup fragments split by
  // comments so that mXSS-style reparsing exposes an unescaped event handler if the
  // bug is present, while the fixed regex requires a terminating '}' and behaves
  // differently, preventing the same mutation path.
  const payload =
    '<svg><style>${</style><img src=x onerror="window.__' + marker + '_PWNED__=1">' + '}</svg>';

  let maliciousOutput;
  try {
    maliciousOutput = DOMPurify.sanitize(payload, { SAFE_FOR_TEMPLATES: true });
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:true, exploit_succeeded:false, evidence:'malicious sanitize threw (blocked): ' + String(e && e.message)}));
    return;
  }

  const hasDangerousOnerror = /onerror\s*=/i.test(maliciousOutput) && /<img/i.test(maliciousOutput);
  const hasScriptTag = /<script/i.test(maliciousOutput);

  let exploit_succeeded = false;
  let evidence = '';
  if (hasDangerousOnerror || hasScriptTag) {
    exploit_succeeded = true;
    evidence = 'Sanitized output retained dangerous markup under SAFE_FOR_TEMPLATES: ' + maliciousOutput.slice(0, 300);
  } else {
    exploit_succeeded = false;
    evidence = 'Sanitized output did not retain dangerous markup: ' + maliciousOutput.slice(0, 300);
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed, exploit_succeeded, evidence}));
}

try {
  run();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:false, exploit_succeeded:false, evidence:'unexpected top-level exception: ' + String(e && e.message)}));
}
