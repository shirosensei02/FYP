let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const dp = require('dompurify');

  const win = {
    document: {
      nodeType: 9,
      createElement: function (tag) {
        const el = {
          nodeName: String(tag || '').toUpperCase(),
          attributes: [],
          childNodes: [],
          style: {},
          setAttribute: function (name, value) {
            this.attributes.push({ name: String(name), value: String(value) });
            this[name] = String(value);
          },
          removeAttribute: function () {},
          appendChild: function (c) { this.childNodes.push(c); return c; },
          cloneNode: function () { return this; }
        };
        return el;
      },
      createElementNS: function (_ns, tag) { return this.createElement(tag); },
      createTextNode: function (text) { return { nodeType: 3, data: String(text) }; },
      createComment: function (text) { return { nodeType: 8, data: String(text) }; },
      createDocumentFragment: function () { return { nodeType: 11, childNodes: [], appendChild: function (c) { this.childNodes.push(c); return c; } }; },
      getElementsByTagName: function () { return []; },
      querySelector: function () { return null; },
      querySelectorAll: function () { return []; },
      body: { innerHTML: '', childNodes: [], appendChild: function (c) { this.childNodes.push(c); return c; } },
      documentElement: { nodeName: 'HTML' },
      implementation: {
        createHTMLDocument: function () {
          return {
            body: { innerHTML: '', childNodes: [], appendChild: function (c) { this.childNodes.push(c); return c; } },
            documentElement: { nodeName: 'HTML' },
            createElement: function (tag) { return win.document.createElement(tag); },
            createElementNS: function (ns, tag) { return win.document.createElementNS(ns, tag); },
            createTextNode: function (text) { return win.document.createTextNode(text); },
            createComment: function (text) { return win.document.createComment(text); },
            createDocumentFragment: function () { return win.document.createDocumentFragment(); },
            getElementsByTagName: function () { return []; },
            querySelector: function () { return null; },
            querySelectorAll: function () { return []; }
          };
        }
      }
    },
    Node: { ELEMENT_NODE: 1, TEXT_NODE: 3, COMMENT_NODE: 8, DOCUMENT_FRAGMENT_NODE: 11 },
    Element: function Element() {},
    HTMLElement: function HTMLElement() {},
    DocumentFragment: function DocumentFragment() {},
    navigator: { userAgent: 'node' }
  };
  win.window = win;
  win.self = win;

  const create = (dp && dp.default) ? dp.default : dp;
  const DOMPurify = typeof create === 'function' ? create(win) : create;

  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('DOMPurify.sanitize is not a function');
  }

  const benignOut = DOMPurify.sanitize('<p>Hello</p>');
  if (typeof benignOut !== 'string' || benignOut.toLowerCase().indexOf('hello') === -1) {
    throw new Error('benign sanitize failed: unexpected output: ' + String(benignOut));
  }

  operation_completed = true;

  const maliciousInput = '<svg><g/onload=alert(1)></g></svg>';
  let maliciousOut;
  try {
    maliciousOut = DOMPurify.sanitize(maliciousInput, { USE_PROFILES: { svg: true, svgFilters: true, html: false } });
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (err && err.message ? err.message : String(err));
    emit();
    return;
  }

  const out = String(maliciousOut);
  const hasHandler = /\son[a-z0-9_-]+\s*=\s*/i.test(out);
  exploit_succeeded = hasHandler;
  evidence = JSON.stringify({ benignOut: String(benignOut), maliciousOut: out, hasHandler: hasHandler });
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

emit();