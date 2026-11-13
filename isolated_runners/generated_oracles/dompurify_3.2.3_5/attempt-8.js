(function () {
  var operation_completed = false;
  var exploit_succeeded = false;
  var evidence = '';

  try {
    var createDOMPurify = require('dompurify');

    if (typeof createDOMPurify !== 'function') {
      throw new Error('dompurify export is not a function');
    }

    function makeInertElement(tag) {
      return {
        nodeName: String(tag || '').toUpperCase(),
        namespaceURI: 'http://www.w3.org/1999/xhtml',
        attributes: [],
        childNodes: [],
        parentNode: null,
        style: {},
        _html: '',
        appendChild: function (n) { this.childNodes.push(n); n.parentNode = this; return n; },
        removeChild: function (n) { var i = this.childNodes.indexOf(n); if (i >= 0) this.childNodes.splice(i, 1); return n; },
        cloneNode: function () { return makeInertElement(tag); },
        setAttribute: function () {},
        getAttribute: function () { return null; },
        hasAttribute: function () { return false; },
        removeAttribute: function () {},
        insertBefore: function (n) { this.childNodes.push(n); n.parentNode = this; return n; },
        querySelector: function () { return null; },
        querySelectorAll: function () { return []; },
        getElementsByTagName: function () { return []; },
        getElementsByTagNameNS: function () { return []; }
      };
    }

    var document = {
      nodeType: 9,
      documentElement: makeInertElement('html'),
      body: makeInertElement('body'),
      head: makeInertElement('head'),
      defaultView: null,
      createElement: function (tag) { return makeInertElement(tag); },
      createElementNS: function (ns, tag) {
        var el = makeInertElement(tag);
        el.namespaceURI = ns || null;
        return el;
      },
      createTextNode: function (text) { return { nodeType: 3, data: String(text || ''), parentNode: null }; },
      createComment: function (text) { return { nodeType: 8, data: String(text || ''), parentNode: null }; },
      importNode: function (node) { return node; },
      querySelector: function () { return null; },
      querySelectorAll: function () { return []; },
      getElementsByTagName: function () { return []; },
      getElementsByTagNameNS: function () { return []; },
      implementation: {
        createHTMLDocument: function () {
          return document;
        }
      }
    };

    var windowObj = {
      document: document,
      navigator: { userAgent: 'node' },
      location: { href: 'https://example.test/' },
      Node: function Node() {},
      Element: function Element() {},
      HTMLElement: function HTMLElement() {},
      DocumentFragment: function DocumentFragment() {},
      HTMLTemplateElement: function HTMLTemplateElement() {},
      setTimeout: function (fn) { if (typeof fn === 'function') fn(); return 0; },
      clearTimeout: function () {}
    };
    document.defaultView = windowObj;

    var DOMPurify = createDOMPurify(windowObj);
    if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
      throw new Error('sanitize API unavailable');
    }

    var benign = '<p>Hello <b>world</b></p>';
    var benignOut = DOMPurify.sanitize(benign);
    if (typeof benignOut !== 'string' || benignOut.indexOf('Hello') === -1) {
      throw new Error('benign sanitize failed');
    }

    operation_completed = true;

    var payload = '<svg><g/onload=alert(1)//<p>';
    var maliciousOut = String(DOMPurify.sanitize(payload));

    var keptOnload = /onload\s*=\s*/i.test(maliciousOut);
    var keptAlert = /alert\s*\(/i.test(maliciousOut);
    exploit_succeeded = keptOnload || keptAlert;

    evidence = 'benign_ok=true;malicious_out=' + JSON.stringify(maliciousOut).slice(0, 200) + ';keptOnload=' + keptOnload + ';keptAlert=' + keptAlert;
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