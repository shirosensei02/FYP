const fs = require('node:fs');
const path = require('node:path');

(function () {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = path.join('/tmp', 'oracle-dompurify-' + Date.now() + '-' + Math.random().toString(16).slice(2) + '.txt');
    fs.writeFileSync(marker, 'start', 'utf8');

    const createDOMPurify = require('dompurify');
    if (typeof createDOMPurify !== 'function') {
      throw new Error('dompurify export is not a function');
    }

    const window = {
      document: {
        nodeType: 9,
        documentElement: { nodeName: 'HTML' },
        createElement: function () { return {}; },
        createElementNS: function () { return {}; },
        implementation: {
          createHTMLDocument: function () {
            return {
              documentElement: { nodeName: 'HTML' },
              body: { innerHTML: '' }
            };
          }
        }
      },
      Node: function Node() {},
      Element: function Element() {},
      DocumentFragment: function DocumentFragment() {},
      HTMLTemplateElement: function HTMLTemplateElement() {},
      navigator: { userAgent: 'node' },
      location: { href: 'https://example.test/' }
    };
    window.Node.prototype = {};
    window.Element.prototype = Object.create(window.Node.prototype);
    window.DocumentFragment.prototype = Object.create(window.Node.prototype);
    window.HTMLTemplateElement.prototype = Object.create(window.Element.prototype);

    const purify = createDOMPurify(window);
    if (!purify || typeof purify.sanitize !== 'function') {
      throw new Error('sanitize API missing');
    }

    const benign = '<p>Hello <b>world</b></p>';
    const benignOut = purify.sanitize(benign);
    if (typeof benignOut !== 'string') {
      throw new Error('benign sanitize did not return string');
    }

    operation_completed = true;

    const malicious = '<img src=x onerror=alert(1)><svg><g/onload=alert(2)//<p>';
    const maliciousOut = purify.sanitize(malicious);
    const out = String(maliciousOut);

    const hasOnerror = /onerror\s*=/i.test(out);
    const hasOnload = /onload\s*=/i.test(out);
    const hasJs = /javascript\s*:/i.test(out);

    exploit_succeeded = hasOnerror || hasOnload || hasJs;
    evidence = 'benign_len=' + benignOut.length + ';mal_len=' + out.length + ';flags=' + [hasOnerror, hasOnload, hasJs].join(',') + ';marker=' + marker;
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'exception:' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed: operation_completed, exploit_succeeded: exploit_succeeded, evidence: evidence }));
})();