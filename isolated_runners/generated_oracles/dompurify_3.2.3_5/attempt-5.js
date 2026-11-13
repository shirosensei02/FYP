(function () {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const createDOMPurify = require('dompurify');
    if (typeof createDOMPurify !== 'function') {
      throw new Error('dompurify export is not a function');
    }

    // Minimal fake DOM implementation sufficient for DOMPurify initialization
    const fakeDocument = {
      nodeType: 9,
      documentElement: { nodeName: 'HTML', namespaceURI: 'http://www.w3.org/1999/xhtml' },
      body: { nodeName: 'BODY', namespaceURI: 'http://www.w3.org/1999/xhtml' },
      createElement: function (name) {
        return {
          nodeName: String(name || '').toUpperCase(),
          namespaceURI: 'http://www.w3.org/1999/xhtml',
          attributes: [],
          childNodes: [],
          setAttribute: function () {},
          removeAttribute: function () {},
          appendChild: function () { return null; },
          cloneNode: function () { return this; }
        };
      },
      createElementNS: function (ns, name) {
        return {
          nodeName: String(name || '').toUpperCase(),
          namespaceURI: ns || null,
          attributes: [],
          childNodes: [],
          setAttribute: function () {},
          removeAttribute: function () {},
          appendChild: function () { return null; },
          cloneNode: function () { return this; }
        };
      },
      createTextNode: function (text) { return { nodeType: 3, data: String(text || '') }; },
      createComment: function (text) { return { nodeType: 8, data: String(text || '') }; },
      implementation: {
        createHTMLDocument: function () {
          return {
            documentElement: { nodeName: 'HTML', namespaceURI: 'http://www.w3.org/1999/xhtml' },
            body: { innerHTML: '' },
            createElement: fakeDocument.createElement,
            createElementNS: fakeDocument.createElementNS,
            createTextNode: fakeDocument.createTextNode,
            createComment: fakeDocument.createComment
          };
        }
      }
    };

    const fakeWindow = {
      document: fakeDocument,
      Node: function Node() {},
      Element: function Element() {},
      DocumentFragment: function DocumentFragment() {},
      HTMLTemplateElement: function HTMLTemplateElement() {},
      navigator: { userAgent: 'node' },
      location: { href: 'https://example.test/' }
    };
    fakeWindow.Node.prototype = {};
    fakeWindow.Element.prototype = Object.create(fakeWindow.Node.prototype);
    fakeWindow.DocumentFragment.prototype = Object.create(fakeWindow.Node.prototype);
    fakeWindow.HTMLTemplateElement.prototype = Object.create(fakeWindow.Element.prototype);

    const purify = createDOMPurify(fakeWindow);
    if (!purify || typeof purify.isSupported !== 'boolean') {
      throw new Error('failed to initialize DOMPurify instance');
    }

    // Benign operation: public API call that should always work
    const benignInput = 'hello-safe-text';
    const benignOut = purify.sanitize(benignInput);
    if (typeof benignOut !== 'string') {
      throw new Error('benign sanitize did not return string');
    }

    operation_completed = true;

    // Malicious probe: check if obvious dangerous attribute survives sanitization
    const maliciousInput = '<img src=x onerror=alert(1)><svg><g/onload=alert(2)//<p>';
    const maliciousOut = String(purify.sanitize(maliciousInput));
    const hasOnerror = /onerror\s*=/i.test(maliciousOut);
    const hasOnload = /onload\s*=/i.test(maliciousOut);
    const hasJavascript = /javascript\s*:/i.test(maliciousOut);

    exploit_succeeded = hasOnerror || hasOnload || hasJavascript;
    evidence = 'supported=' + purify.isSupported + ';benign_len=' + benignOut.length + ';mal_len=' + maliciousOut.length + ';flags=' + [hasOnerror, hasOnload, hasJavascript].join(',');
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'exception:' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: operation_completed,
    exploit_succeeded: exploit_succeeded,
    evidence: evidence
  }));
})();