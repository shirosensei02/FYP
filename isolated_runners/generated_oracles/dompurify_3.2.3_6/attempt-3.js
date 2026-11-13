const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

function printResult() {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function makeMinimalWindow() {
  const NodeFilter = {
    SHOW_ELEMENT: 1,
    SHOW_COMMENT: 128,
    SHOW_TEXT: 4,
    SHOW_PROCESSING_INSTRUCTION: 64,
    SHOW_CDATA_SECTION: 8
  };

  function FakeNode(nodeType, nodeName, ownerDocument) {
    this.nodeType = nodeType;
    this.nodeName = nodeName;
    this.ownerDocument = ownerDocument || null;
    this.parentNode = null;
    this.childNodes = [];
    this.attributes = [];
    this.namespaceURI = 'http://www.w3.org/1999/xhtml';
    this.textContent = '';
  }
  FakeNode.prototype.appendChild = function (n) {
    n.parentNode = this;
    this.childNodes.push(n);
    return n;
  };
  FakeNode.prototype.removeChild = function (n) {
    const i = this.childNodes.indexOf(n);
    if (i >= 0) this.childNodes.splice(i, 1);
    n.parentNode = null;
    return n;
  };
  FakeNode.prototype.insertBefore = function (n, ref) {
    n.parentNode = this;
    if (!ref) {
      this.childNodes.push(n);
      return n;
    }
    const i = this.childNodes.indexOf(ref);
    if (i < 0) this.childNodes.push(n);
    else this.childNodes.splice(i, 0, n);
    return n;
  };
  Object.defineProperty(FakeNode.prototype, 'firstChild', {
    get: function () {
      return this.childNodes.length ? this.childNodes[0] : null;
    }
  });
  Object.defineProperty(FakeNode.prototype, 'firstElementChild', {
    get: function () {
      for (let i = 0; i < this.childNodes.length; i++) {
        if (this.childNodes[i].nodeType === 1) return this.childNodes[i];
      }
      return null;
    }
  });
  FakeNode.prototype.hasChildNodes = function () {
    return this.childNodes.length > 0;
  };
  FakeNode.prototype.cloneNode = function () {
    const c = new FakeNode(this.nodeType, this.nodeName, this.ownerDocument);
    c.textContent = this.textContent;
    c.namespaceURI = this.namespaceURI;
    return c;
  };

  function FakeElement(name, doc) {
    FakeNode.call(this, 1, String(name || '').toUpperCase(), doc);
    this.tagName = this.nodeName;
  }
  FakeElement.prototype = Object.create(FakeNode.prototype);
  FakeElement.prototype.constructor = FakeElement;
  FakeElement.prototype.setAttribute = function (name, value) {
    const n = String(name);
    const v = String(value);
    for (let i = 0; i < this.attributes.length; i++) {
      if (this.attributes[i].name === n) {
        this.attributes[i].value = v;
        return;
      }
    }
    this.attributes.push({ name: n, value: v, namespaceURI: null });
  };
  FakeElement.prototype.removeAttribute = function (name) {
    const n = String(name);
    this.attributes = this.attributes.filter(function (a) { return a.name !== n; });
  };
  FakeElement.prototype.getAttributeNode = function (name) {
    const n = String(name);
    for (let i = 0; i < this.attributes.length; i++) if (this.attributes[i].name === n) return this.attributes[i];
    return null;
  };
  FakeElement.prototype.setAttributeNS = function (_ns, name, value) {
    this.setAttribute(name, value);
  };

  function FakeDocument() {
    this.nodeType = 9;
    this.documentElement = new FakeElement('html', this);
    this.body = new FakeElement('body', this);
    this.documentElement.appendChild(this.body);
    this.implementation = {
      createHTMLDocument: () => new FakeDocument(),
      createDocument: () => new FakeDocument()
    };
  }
  FakeDocument.prototype.createElement = function (name) {
    return new FakeElement(name, this);
  };
  FakeDocument.prototype.createTextNode = function (text) {
    const n = new FakeNode(3, '#text', this);
    n.textContent = String(text);
    return n;
  };
  FakeDocument.prototype.createDocumentFragment = function () {
    return new FakeNode(11, '#document-fragment', this);
  };
  FakeDocument.prototype.importNode = function (n) { return n; };
  FakeDocument.prototype.getElementsByTagName = function (name) {
    if (String(name).toLowerCase() === 'body') return [this.body];
    if (String(name).toLowerCase() === 'html') return [this.documentElement];
    return [];
  };
  FakeDocument.prototype.createNodeIterator = function (root) {
    const nodes = [];
    (function walk(n) {
      nodes.push(n);
      if (n && n.childNodes) {
        for (let i = 0; i < n.childNodes.length; i++) walk(n.childNodes[i]);
      }
    })(root);
    let idx = 0;
    return { nextNode: function () { return idx < nodes.length ? nodes[idx++] : null; } };
  };

  function DOMParser() {}
  DOMParser.prototype.parseFromString = function () {
    return new FakeDocument();
  };

  const doc = new FakeDocument();
  return {
    document: doc,
    NodeFilter,
    Node: FakeNode,
    Element: FakeElement,
    HTMLFormElement: function HTMLFormElement() {},
    NamedNodeMap: Array,
    DOMParser,
    trustedTypes: null
  };
}

try {
  const createDOMPurify = require('dompurify');
  const win = makeMinimalWindow();
  const purify = createDOMPurify(win);

  if (!purify || typeof purify.sanitize !== 'function') {
    throw new Error('sanitize API unavailable');
  }

  const benign = 'hello world';
  const benignOut = purify.sanitize(benign, { SAFE_FOR_TEMPLATES: true });
  if (typeof benignOut !== 'string') {
    throw new Error('benign output not string');
  }

  result.operation_completed = true;

  const malicious = '${alert(1)';
  try {
    const out = purify.sanitize(malicious, { SAFE_FOR_TEMPLATES: true });
    const leaked = typeof out === 'string' && out.indexOf('${') !== -1;
    result.exploit_succeeded = leaked;
    result.evidence = JSON.stringify({ benignOut: benignOut, maliciousOut: out, leakedTemplateToken: leaked });
  } catch (e) {
    result.exploit_succeeded = false;
    result.evidence = 'malicious_blocked:' + (e && e.message ? e.message : String(e));
  }
} catch (e) {
  result.operation_completed = false;
  result.exploit_succeeded = false;
  result.evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

printResult();