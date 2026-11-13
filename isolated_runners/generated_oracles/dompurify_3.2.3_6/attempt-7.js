const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

function done() {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const createDOMPurify = require('dompurify');

  // Tiny deterministic fake DOM sufficient for string sanitization path.
  function makeWindow() {
    function BaseNode() {}

    function makeTextNode(text, ownerDocument) {
      return {
        nodeType: 3,
        data: String(text),
        textContent: String(text),
        ownerDocument,
        parentNode: null,
        cloneNode: function () {
          return makeTextNode(this.data, ownerDocument);
        }
      };
    }

    function makeElement(tagName, ownerDocument) {
      const el = {
        nodeType: 1,
        tagName: String(tagName || 'DIV').toUpperCase(),
        nodeName: String(tagName || 'DIV').toUpperCase(),
        namespaceURI: 'http://www.w3.org/1999/xhtml',
        ownerDocument,
        parentNode: null,
        attributes: [],
        childNodes: [],
        _innerHTML: '',
        get firstChild() { return this.childNodes[0] || null; },
        get firstElementChild() { return null; },
        get textContent() { return this._innerHTML; },
        set textContent(v) { this._innerHTML = String(v); this.childNodes = []; },
        get innerHTML() { return this._innerHTML; },
        set innerHTML(v) { this._innerHTML = String(v); this.childNodes = []; },
        get outerHTML() { return '<' + this.tagName.toLowerCase() + '>' + this._innerHTML + '</' + this.tagName.toLowerCase() + '>'; },
        hasChildNodes: function () { return this.childNodes.length > 0; },
        appendChild: function (n) { if (n) { n.parentNode = this; this.childNodes.push(n); } return n; },
        insertBefore: function (n) { return this.appendChild(n); },
        removeChild: function (n) { const i = this.childNodes.indexOf(n); if (i >= 0) this.childNodes.splice(i, 1); return n; },
        remove: function () {},
        cloneNode: function () { const c = makeElement(this.tagName, ownerDocument); c._innerHTML = this._innerHTML; return c; },
        setAttribute: function () {},
        setAttributeNS: function () {},
        removeAttribute: function () {},
        getAttributeNode: function () { return null; }
      };
      return el;
    }

    function makeDoc() {
      const doc = {
        nodeType: 9,
        documentElement: null,
        body: null,
        currentScript: null,
        implementation: {
          createHTMLDocument: function () {
            return makeDoc();
          },
          createDocument: function () {
            return makeDoc();
          }
        },
        createElement: function (tag) {
          const el = makeElement(tag, doc);
          if (String(tag).toLowerCase() === 'template') {
            el.content = { ownerDocument: doc };
          }
          return el;
        },
        createTextNode: function (t) { return makeTextNode(t, doc); },
        createDocumentFragment: function () {
          return { nodeType: 11, ownerDocument: doc, childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; }, firstChild: null };
        },
        importNode: function (n) { return n; },
        getElementsByTagName: function (name) {
          const lower = String(name).toLowerCase();
          if (lower === 'body') return [doc.body];
          if (lower === 'html') return [doc.documentElement];
          return [];
        },
        createNodeIterator: function () {
          return { nextNode: function () { return null; } };
        }
      };
      doc.documentElement = makeElement('html', doc);
      doc.body = makeElement('body', doc);
      doc.documentElement.appendChild(doc.body);
      return doc;
    }

    function ElementCtor() {}
    ElementCtor.prototype = {
      cloneNode: function () { return this; },
      remove: function () {},
      get nextSibling() { return null; },
      get childNodes() { return []; },
      get parentNode() { return null; }
    };

    return {
      document: makeDoc(),
      Element: ElementCtor,
      Node: BaseNode,
      NodeFilter: {
        SHOW_ELEMENT: 1,
        SHOW_COMMENT: 2,
        SHOW_TEXT: 4,
        SHOW_PROCESSING_INSTRUCTION: 8,
        SHOW_CDATA_SECTION: 16
      },
      NamedNodeMap: function NamedNodeMap() {},
      HTMLFormElement: function HTMLFormElement() {},
      DOMParser: function DOMParser() {
        this.parseFromString = function () { return makeDoc(); };
      }
    };
  }

  const DOMPurify = createDOMPurify(makeWindow());
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('sanitize_unavailable');
  }

  const benignInput = 'hello world';
  const benignOutput = DOMPurify.sanitize(benignInput, { SAFE_FOR_TEMPLATES: true });
  if (typeof benignOutput !== 'string' || benignOutput !== benignInput) {
    throw new Error('benign_behavior_unexpected');
  }

  result.operation_completed = true;

  const maliciousInput = 'prefix ${alert(1)';
  try {
    const out = DOMPurify.sanitize(maliciousInput, { SAFE_FOR_TEMPLATES: true });
    const exploit = typeof out === 'string' && out.indexOf('${') !== -1;
    result.exploit_succeeded = exploit;
    result.evidence = JSON.stringify({ malicious_input: maliciousInput, malicious_output: out, template_marker_present: exploit });
  } catch (err) {
    result.exploit_succeeded = false;
    result.evidence = 'malicious_input_rejected';
  }
} catch (e) {
  result.operation_completed = false;
  result.exploit_succeeded = false;
  result.evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

done();