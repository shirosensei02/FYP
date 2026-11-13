let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function done() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');

  function createWindowLike() {
    function makeNode(type, name) {
      return {
        nodeType: type,
        nodeName: name,
        parentNode: null,
        childNodes: [],
        appendChild(c) {
          if (c) {
            c.parentNode = this;
            this.childNodes.push(c);
          }
          return c;
        },
        removeChild(c) {
          const i = this.childNodes.indexOf(c);
          if (i >= 0) this.childNodes.splice(i, 1);
          if (c) c.parentNode = null;
          return c;
        }
      };
    }

    function makeElement(tag) {
      const e = makeNode(1, String(tag || '').toUpperCase());
      e.tagName = e.nodeName;
      e.namespaceURI = 'http://www.w3.org/1999/xhtml';
      e.attributes = [];
      e.setAttribute = function (k, v) {
        const key = String(k);
        const val = String(v);
        const idx = this.attributes.findIndex((a) => a.name === key);
        if (idx >= 0) this.attributes[idx].value = val;
        else this.attributes.push({ name: key, value: val });
      };
      e.getAttribute = function (k) {
        const key = String(k);
        const hit = this.attributes.find((a) => a.name === key);
        return hit ? hit.value : null;
      };
      e.hasAttribute = function (k) {
        const key = String(k);
        return this.attributes.some((a) => a.name === key);
      };
      e.removeAttribute = function (k) {
        const key = String(k);
        this.attributes = this.attributes.filter((a) => a.name !== key);
      };
      e.querySelectorAll = function () { return []; };
      e.getElementsByTagName = function () { return []; };
      Object.defineProperty(e, 'firstChild', { get() { return this.childNodes[0] || null; } });
      return e;
    }

    function makeDocument() {
      const d = makeNode(9, '#document');
      d.documentElement = makeElement('html');
      d.head = makeElement('head');
      d.body = makeElement('body');
      d.documentElement.appendChild(d.head);
      d.documentElement.appendChild(d.body);
      d.createElement = (t) => makeElement(t);
      d.createElementNS = (_ns, t) => makeElement(t);
      d.createTextNode = (txt) => ({ nodeType: 3, nodeName: '#text', data: String(txt), textContent: String(txt), parentNode: null });
      d.createComment = (txt) => ({ nodeType: 8, nodeName: '#comment', data: String(txt), parentNode: null });
      d.createDocumentFragment = () => makeNode(11, '#document-fragment');
      d.importNode = (n) => n;
      d.querySelectorAll = () => [];
      d.getElementsByTagName = () => [];
      d.addEventListener = () => {};
      d.removeEventListener = () => {};
      d.implementation = {
        createHTMLDocument: () => makeDocument()
      };
      return d;
    }

    const document = makeDocument();

    function DOMParser() {}
    DOMParser.prototype.parseFromString = function () {
      return makeDocument();
    };

    return {
      document,
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

  const win = createWindowLike();
  const DOMPurify = createDOMPurify(win);
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('DOMPurify.sanitize unavailable');
  }

  let benign;
  try {
    benign = String(DOMPurify.sanitize('<p>Hello</p>'));
  } catch (e) {
    evidence = 'benign sanitize threw: ' + (e && e.message ? e.message : String(e));
    done();
    return;
  }

  if (!/Hello/.test(benign)) {
    evidence = 'benign sanitize unexpected: ' + JSON.stringify(benign);
    done();
    return;
  }

  operation_completed = true;

  const payload = '<svg><g/onload=alert(1)//<p>';
  try {
    const out = String(DOMPurify.sanitize(payload));
    const hasOnload = /onload\s*=|onload\b/i.test(out);
    const hasScriptLike = /<script\b|alert\s*\(/i.test(out);
    exploit_succeeded = hasOnload || hasScriptLike;
    evidence = 'output=' + JSON.stringify(out) + ';hasOnload=' + hasOnload + ';hasScriptLike=' + hasScriptLike;
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious sanitize threw after benign success: ' + (e && e.message ? e.message : String(e));
  }

  done();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/module error: ' + (e && e.message ? e.message : String(e));
  done();
}
