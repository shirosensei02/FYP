const fs = require('node:fs');
const path = require('node:path');

(function () {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const markerDir = path.join('/tmp', 'oracle-dompurify-' + Date.now() + '-' + Math.random().toString(16).slice(2));
    fs.mkdirSync(markerDir, { recursive: true });

    const createDOMPurify = require('dompurify');
    if (typeof createDOMPurify !== 'function') {
      throw new Error('dompurify export is not a factory function');
    }

    const fakeWindow = {
      document: {
        nodeType: 9,
        createElement: function (tag) {
          const attrMap = Object.create(null);
          return {
            nodeType: 1,
            nodeName: String(tag || '').toUpperCase(),
            attributes: [],
            childNodes: [],
            style: {},
            namespaceURI: 'http://www.w3.org/1999/xhtml',
            parentNode: null,
            ownerDocument: this,
            setAttribute: function (name, value) {
              attrMap[name] = String(value);
            },
            getAttribute: function (name) {
              return Object.prototype.hasOwnProperty.call(attrMap, name) ? attrMap[name] : null;
            },
            removeAttribute: function (name) {
              delete attrMap[name];
            },
            appendChild: function (n) {
              this.childNodes.push(n);
              n.parentNode = this;
              return n;
            },
            removeChild: function (n) {
              const i = this.childNodes.indexOf(n);
              if (i >= 0) this.childNodes.splice(i, 1);
              return n;
            },
            cloneNode: function () {
              return this;
            },
            querySelector: function () {
              return null;
            },
            querySelectorAll: function () {
              return [];
            }
          };
        },
        createElementNS: function (_ns, tag) {
          return this.createElement(tag);
        },
        createTextNode: function (text) {
          return { nodeType: 3, nodeValue: String(text), textContent: String(text), parentNode: null };
        },
        createComment: function (text) {
          return { nodeType: 8, nodeValue: String(text), parentNode: null };
        },
        createDocumentFragment: function () {
          return {
            nodeType: 11,
            childNodes: [],
            appendChild: function (n) { this.childNodes.push(n); return n; },
            removeChild: function (n) { const i = this.childNodes.indexOf(n); if (i >= 0) this.childNodes.splice(i, 1); return n; }
          };
        },
        implementation: {
          createHTMLDocument: function () {
            return fakeWindow.document;
          }
        },
        body: {
          childNodes: [],
          appendChild: function (n) { this.childNodes.push(n); return n; },
          removeChild: function (n) { const i = this.childNodes.indexOf(n); if (i >= 0) this.childNodes.splice(i, 1); return n; }
        },
        head: {
          appendChild: function (n) { return n; }
        },
        documentElement: {
          nodeName: 'HTML'
        }
      },
      Node: { ELEMENT_NODE: 1, TEXT_NODE: 3, COMMENT_NODE: 8, DOCUMENT_FRAGMENT_NODE: 11 },
      Element: function Element() {},
      DocumentFragment: function DocumentFragment() {},
      HTMLTemplateElement: function HTMLTemplateElement() {},
      DOMParser: function DOMParser() {
        this.parseFromString = function () {
          return fakeWindow.document;
        };
      },
      navigator: { userAgent: 'node' },
      location: { href: 'https://example.test/' }
    };

    const purify = createDOMPurify(fakeWindow);
    if (!purify || typeof purify.sanitize !== 'function') {
      throw new Error('failed to initialize sanitize API');
    }

    const benignInput = '<p>Hello <b>world</b></p>';
    const benignOutput = purify.sanitize(benignInput);
    if (typeof benignOutput !== 'string' || benignOutput.indexOf('<b>world</b>') === -1) {
      throw new Error('benign sanitize did not preserve expected safe markup');
    }

    operation_completed = true;

    const maliciousInput = '<img src=x onerror=alert(1)><svg><g/onload=alert(2)//<p>';
    const maliciousOutput = purify.sanitize(maliciousInput);

    const hasOnerror = /onerror\s*=\s*/i.test(maliciousOutput);
    const hasOnload = /onload\s*=\s*/i.test(maliciousOutput);
    const hasScriptScheme = /javascript\s*:/i.test(maliciousOutput);

    exploit_succeeded = hasOnerror || hasOnload || hasScriptScheme;
    evidence = 'benign_len=' + benignOutput.length + ';malicious_len=' + String(maliciousOutput).length + ';flags=' + [hasOnerror, hasOnload, hasScriptScheme].join(',') + ';marker=' + markerDir;
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'exception:' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed: operation_completed, exploit_succeeded: exploit_succeeded, evidence: evidence }));
})();