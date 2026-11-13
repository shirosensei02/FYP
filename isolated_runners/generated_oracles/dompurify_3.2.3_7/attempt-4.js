let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');

  // Minimal DOM-like window tailored to avoid instanceof/callability crashes
  function NodeCtor() {}
  function ElementCtor() {}
  function HTMLElementCtor() {}
  function DocumentFragmentCtor() {}
  function HTMLTemplateElementCtor() {}

  const windowLike = {
    Node: NodeCtor,
    Element: ElementCtor,
    HTMLElement: HTMLElementCtor,
    DocumentFragment: DocumentFragmentCtor,
    HTMLTemplateElement: HTMLTemplateElementCtor,
    navigator: { userAgent: 'node-oracle' },
    document: {
      nodeType: 9,
      documentElement: { nodeName: 'HTML' },
      createElement: function () {
        return {
          nodeType: 1,
          nodeName: 'DIV',
          innerHTML: '',
          textContent: '',
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
          nodeType: 1,
          nodeName: 'svg',
          innerHTML: '',
          textContent: '',
          childNodes: [],
          attributes: [],
          setAttribute: function () {},
          removeAttribute: function () {},
          appendChild: function (n) { this.childNodes.push(n); return n; },
          cloneNode: function () { return this; }
        };
      },
      createTextNode: function (t) { return { nodeType: 3, data: String(t || '') }; },
      createDocumentFragment: function () {
        return { nodeType: 11, childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } };
      },
      getElementsByTagName: function () { return []; },
      implementation: {
        createHTMLDocument: function () {
          return {
            nodeType: 9,
            documentElement: { nodeName: 'HTML' },
            body: {
              innerHTML: '',
              childNodes: [],
              appendChild: function (n) { this.childNodes.push(n); return n; }
            },
            createElement: function () {
              return {
                nodeType: 1,
                nodeName: 'DIV',
                innerHTML: '',
                textContent: '',
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
                nodeType: 1,
                nodeName: 'svg',
                innerHTML: '',
                textContent: '',
                childNodes: [],
                attributes: [],
                setAttribute: function () {},
                removeAttribute: function () {},
                appendChild: function (n) { this.childNodes.push(n); return n; },
                cloneNode: function () { return this; }
              };
            },
            createTextNode: function (t) { return { nodeType: 3, data: String(t || '') }; },
            createDocumentFragment: function () {
              return { nodeType: 11, childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } };
            },
            getElementsByTagName: function () { return []; }
          };
        }
      }
    }
  };

  const DOMPurify = createDOMPurify(windowLike);

  const benignInput = '<p>Hello</p>';
  const benignOut = DOMPurify.sanitize(benignInput);
  if (typeof benignOut !== 'string' || benignOut.indexOf('Hello') === -1) {
    throw new Error('benign sanitize did not return expected output');
  }

  operation_completed = true;

  const maliciousInput = '<math><mi//xlink:href="data:x,<script>alert(1)</script>">X</mi></math>';
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
  const dangerous = /<\s*script\b/i.test(out) || /data\s*:\s*x\s*,\s*<\s*script/i.test(out) || /xlink:href\s*=\s*['"]?\s*data\s*:/i.test(out);
  exploit_succeeded = dangerous;
  evidence = JSON.stringify({ benignOut: benignOut, maliciousOut: out, dangerous: dangerous });
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

emit();