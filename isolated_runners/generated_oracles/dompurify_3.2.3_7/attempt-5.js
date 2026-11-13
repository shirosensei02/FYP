let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');

  function makeElement(name) {
    return {
      nodeType: 1,
      nodeName: String(name || 'DIV').toUpperCase(),
      namespaceURI: 'http://www.w3.org/1999/xhtml',
      attributes: [],
      childNodes: [],
      parentNode: null,
      innerHTML: '',
      textContent: '',
      setAttribute: function (k, v) {
        this.attributes.push({ name: String(k), value: String(v) });
      },
      removeAttribute: function (k) {
        const key = String(k);
        this.attributes = this.attributes.filter((a) => a.name !== key);
      },
      hasAttribute: function (k) {
        const key = String(k);
        return this.attributes.some((a) => a.name === key);
      },
      getAttribute: function (k) {
        const key = String(k);
        const found = this.attributes.find((a) => a.name === key);
        return found ? found.value : null;
      },
      appendChild: function (n) {
        if (n && typeof n === 'object') n.parentNode = this;
        this.childNodes.push(n);
        return n;
      },
      removeChild: function (n) {
        const idx = this.childNodes.indexOf(n);
        if (idx >= 0) this.childNodes.splice(idx, 1);
        return n;
      },
      cloneNode: function () {
        return makeElement(this.nodeName);
      },
      querySelector: function () { return null; },
      querySelectorAll: function () { return []; }
    };
  }

  function makeDocument() {
    const body = makeElement('body');
    const docEl = makeElement('html');
    return {
      nodeType: 9,
      documentElement: docEl,
      body: body,
      head: makeElement('head'),
      createElement: function (name) { return makeElement(name); },
      createElementNS: function (_ns, name) { return makeElement(name); },
      createTextNode: function (t) { return { nodeType: 3, data: String(t || ''), parentNode: null }; },
      createComment: function (t) { return { nodeType: 8, data: String(t || ''), parentNode: null }; },
      createDocumentFragment: function () {
        return {
          nodeType: 11,
          childNodes: [],
          appendChild: function (n) { this.childNodes.push(n); return n; }
        };
      },
      getElementsByTagName: function () { return []; },
      querySelectorAll: function () { return []; },
      implementation: {
        createHTMLDocument: function () { return makeDocument(); },
        createDocument: function () { return makeDocument(); }
      }
    };
  }

  const windowLike = {
    document: makeDocument(),
    Node: function Node() {},
    Element: function Element() {},
    HTMLElement: function HTMLElement() {},
    DocumentFragment: function DocumentFragment() {},
    HTMLTemplateElement: function HTMLTemplateElement() {},
    navigator: { userAgent: 'node' }
  };

  const DOMPurify = createDOMPurify(windowLike);

  const benignInput = '<p>Hello</p>';
  const benignOut = DOMPurify.sanitize(benignInput);
  if (typeof benignOut !== 'string' || benignOut.indexOf('Hello') === -1) {
    throw new Error('benign sanitize failed');
  }

  operation_completed = true;

  const maliciousInput = '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>"></mglyph></table></mtext></math>';
  let maliciousOut;
  try {
    maliciousOut = DOMPurify.sanitize(maliciousInput);
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (err && err.message ? err.message : String(err));
    emit();
    return;
  }

  const out = String(maliciousOut);
  const hasHandler = /on[a-z]+\s*=\s*/i.test(out);
  exploit_succeeded = hasHandler;
  evidence = JSON.stringify({ benignOut: benignOut, maliciousOut: out, hasHandler: hasHandler });
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

emit();