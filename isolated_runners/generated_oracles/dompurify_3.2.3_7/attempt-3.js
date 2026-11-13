let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');

  const windowLike = {
    document: {
      nodeType: 9,
      createElement: function () {
        return {
          nodeName: 'DIV',
          textContent: '',
          innerHTML: '',
          childNodes: [],
          attributes: [],
          setAttribute: function () {},
          removeAttribute: function () {},
          appendChild: function (n) { this.childNodes.push(n); return n; },
          cloneNode: function () { return this; }
        };
      },
      createElementNS: function () {
        return {
          nodeName: 'svg',
          textContent: '',
          innerHTML: '',
          childNodes: [],
          attributes: [],
          setAttribute: function () {},
          removeAttribute: function () {},
          appendChild: function (n) { this.childNodes.push(n); return n; },
          cloneNode: function () { return this; }
        };
      },
      createTextNode: function (t) { return { nodeType: 3, data: String(t || '') }; },
      createDocumentFragment: function () { return { nodeType: 11, childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } }; },
      getElementsByTagName: function () { return []; },
      implementation: {
        createHTMLDocument: function () {
          return {
            body: {
              innerHTML: '',
              childNodes: [],
              appendChild: function (n) { this.childNodes.push(n); return n; }
            },
            documentElement: { nodeName: 'HTML' },
            createElement: function () { return { innerHTML: '', childNodes: [], attributes: [], setAttribute: function () {}, removeAttribute: function () {}, appendChild: function (n) { this.childNodes.push(n); return n; }, cloneNode: function () { return this; } }; },
            createElementNS: function () { return { innerHTML: '', childNodes: [], attributes: [], setAttribute: function () {}, removeAttribute: function () {}, appendChild: function (n) { this.childNodes.push(n); return n; }, cloneNode: function () { return this; } }; },
            createTextNode: function (t) { return { nodeType: 3, data: String(t || '') }; },
            createDocumentFragment: function () { return { nodeType: 11, childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } }; },
            getElementsByTagName: function () { return []; }
          };
        }
      }
    },
    Node: { ELEMENT_NODE: 1, TEXT_NODE: 3, DOCUMENT_FRAGMENT_NODE: 11 },
    Element: function () {},
    HTMLElement: function () {},
    DocumentFragment: function () {},
    HTMLTemplateElement: function () {},
    navigator: { userAgent: 'node-oracle' }
  };

  const DOMPurify = createDOMPurify(windowLike);

  const benignInput = '<p>Hello</p>';
  const benignOut = DOMPurify.sanitize(benignInput);
  if (typeof benignOut !== 'string' || benignOut.indexOf('Hello') === -1) {
    throw new Error('benign sanitize did not return expected output');
  }

  operation_completed = true;

  const maliciousInput = '<svg><g/onload=alert(1)//<p></p></g></svg>';
  let maliciousOut;
  try {
    maliciousOut = DOMPurify.sanitize(maliciousInput);
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (err && err.message ? err.message : String(err));
    emit();
    process.exit(0);
  }

  const out = String(maliciousOut);
  const dangerous = /on[a-z]+\s*=\s*/i.test(out) || /javascript\s*:/i.test(out) || /<\s*script/i.test(out);
  exploit_succeeded = dangerous;
  evidence = JSON.stringify({ benignOut: benignOut, maliciousOut: out, dangerous: dangerous });
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

emit();