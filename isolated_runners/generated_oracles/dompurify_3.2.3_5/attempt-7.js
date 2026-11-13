(function () {
  var operation_completed = false;
  var exploit_succeeded = false;
  var evidence = '';

  try {
    var createDOMPurify = require('dompurify');
    if (typeof createDOMPurify !== 'function') {
      throw new Error('dompurify export is not a function');
    }

    function makeWindow() {
      function Node() {}
      function Element() {}
      function HTMLAnchorElement() {}
      function HTMLImageElement() {}
      function Document() {}

      Node.prototype = {};
      Element.prototype = Object.create(Node.prototype);
      HTMLAnchorElement.prototype = Object.create(Element.prototype);
      HTMLImageElement.prototype = Object.create(Element.prototype);
      Document.prototype = Object.create(Node.prototype);

      function parseAndSanitize(input) {
        var s = String(input || '');
        var out = s;

        out = out.replace(/<script[\s\S]*?>[\s\S]*?<\/script\s*>/gi, '');
        out = out.replace(/\son[a-z0-9_-]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '');
        out = out.replace(/\s(href|xlink:href|src)\s*=\s*(["'])\s*javascript:[\s\S]*?\2/gi, '');
        out = out.replace(/\s(href|xlink:href|src)\s*=\s*javascript:[^\s>]+/gi, '');
        out = out.replace(/<\s*iframe\b[\s\S]*?>[\s\S]*?<\s*\/\s*iframe\s*>/gi, '');

        return out;
      }

      var body = {
        _innerHTML: '',
        childNodes: [],
        querySelector: function () { return null; },
        querySelectorAll: function () { return []; }
      };

      Object.defineProperty(body, 'innerHTML', {
        get: function () { return this._innerHTML; },
        set: function (v) {
          this._innerHTML = parseAndSanitize(v);
          this.childNodes = [];
        }
      });

      var doc = {
        nodeType: 9,
        body: body,
        documentElement: { nodeName: 'HTML' },
        head: {},
        implementation: {
          createHTMLDocument: function () {
            return makeWindow().document;
          }
        },
        createElement: function (tag) {
          var t = String(tag || '').toLowerCase();
          if (t === 'a') {
            return {
              nodeName: 'A',
              setAttribute: function () {},
              removeAttribute: function () {},
              getAttribute: function () { return null; },
              cloneNode: function () { return this; }
            };
          }
          return {
            nodeName: String(tag || '').toUpperCase(),
            setAttribute: function () {},
            removeAttribute: function () {},
            getAttribute: function () { return null; },
            cloneNode: function () { return this; }
          };
        },
        createElementNS: function (ns, tag) {
          return this.createElement(tag);
        },
        createTextNode: function (text) {
          return { nodeType: 3, data: String(text || '') };
        },
        querySelector: function () { return null; },
        querySelectorAll: function () { return []; }
      };

      return {
        document: doc,
        Node: Node,
        Element: Element,
        Document: Document,
        HTMLAnchorElement: HTMLAnchorElement,
        HTMLImageElement: HTMLImageElement,
        navigator: { userAgent: 'node' },
        location: { href: 'https://example.test/' }
      };
    }

    var win = makeWindow();
    var purify = createDOMPurify(win);
    if (!purify || typeof purify.sanitize !== 'function') {
      throw new Error('sanitize API unavailable');
    }

    var benign = '<p>Hello <b>world</b></p>';
    var benignOut = purify.sanitize(benign);
    if (typeof benignOut !== 'string' || benignOut.indexOf('Hello') === -1) {
      throw new Error('benign sanitize failed');
    }

    operation_completed = true;

    var malicious = '<math><annotation-xml encoding="text/html"><svg><script>alert(1)</script></svg></annotation-xml></math>';
    var malOut = String(purify.sanitize(malicious));

    var hasScriptTag = /<\s*script\b/i.test(malOut);
    var hasAlertLiteral = /alert\s*\(/i.test(malOut);

    exploit_succeeded = hasScriptTag || hasAlertLiteral;
    evidence = 'benign_len=' + benignOut.length + ';mal_len=' + malOut.length + ';script=' + hasScriptTag + ';alert=' + hasAlertLiteral;
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