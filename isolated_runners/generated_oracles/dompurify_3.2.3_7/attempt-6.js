let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');

  const fakeDocument = {
    nodeType: 9,
    body: {},
    documentElement: {},
    createElement: function () {
      return {
        nodeType: 1,
        nodeName: 'DIV',
        setAttribute: function () {},
        removeAttribute: function () {},
        hasAttribute: function () { return false; },
        cloneNode: function () { return this; },
        appendChild: function () { return null; },
        removeChild: function () { return null; },
        insertBefore: function () { return null; },
        childNodes: []
      };
    },
    createElementNS: function () { return this.createElement(); },
    createTextNode: function (t) { return { nodeType: 3, data: String(t || '') }; },
    createComment: function (t) { return { nodeType: 8, data: String(t || '') }; },
    createDocumentFragment: function () { return { nodeType: 11, childNodes: [], appendChild: function () {} }; },
    getElementsByTagName: function () { return []; },
    querySelectorAll: function () { return []; },
    implementation: {
      createHTMLDocument: function () { return fakeDocument; },
      createDocument: function () { return fakeDocument; }
    }
  };

  const windowLike = {
    document: fakeDocument,
    navigator: { userAgent: 'node' },
    Node: function Node() {},
    Element: function Element() {},
    HTMLElement: function HTMLElement() {},
    DocumentFragment: function DocumentFragment() {},
    HTMLTemplateElement: function HTMLTemplateElement() {}
  };

  const DOMPurify = createDOMPurify(windowLike);

  const benignInput = '<p>Hello</p>';
  let benignOut;
  try {
    benignOut = DOMPurify.sanitize(benignInput);
  } catch (e) {
    throw new Error('benign sanitize failed: ' + (e && e.message ? e.message : String(e)));
  }

  if (typeof benignOut !== 'string' || benignOut.indexOf('Hello') === -1) {
    throw new Error('benign sanitize failed: unexpected output');
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
  const hasHandler = /\son[a-z]+\s*=\s*/i.test(out);
  exploit_succeeded = hasHandler;
  evidence = JSON.stringify({ benignOut: String(benignOut), maliciousOut: out, hasHandler: hasHandler });
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

emit();