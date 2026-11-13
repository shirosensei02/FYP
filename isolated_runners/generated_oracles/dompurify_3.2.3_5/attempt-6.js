(function () {
  var operation_completed = false;
  var exploit_succeeded = false;
  var evidence = '';

  try {
    var createDOMPurify = require('dompurify');
    if (typeof createDOMPurify !== 'function') {
      throw new Error('dompurify export is not a function');
    }

    function makeInertNode(name, ns) {
      return {
        nodeType: 1,
        nodeName: String(name || '').toUpperCase(),
        namespaceURI: ns || 'http://www.w3.org/1999/xhtml',
        attributes: [],
        childNodes: [],
        parentNode: null,
        firstChild: null,
        nextSibling: null,
        textContent: '',
        setAttribute: function () {},
        getAttribute: function () { return null; },
        removeAttribute: function () {},
        hasAttribute: function () { return false; },
        appendChild: function (n) { this.childNodes.push(n); this.firstChild = this.childNodes[0] || null; return n; },
        removeChild: function (n) { return n; },
        insertBefore: function (n) { this.childNodes.push(n); this.firstChild = this.childNodes[0] || null; return n; },
        cloneNode: function () { return makeInertNode(name, ns); },
        querySelectorAll: function () { return []; },
        getElementsByTagName: function () { return []; },
        getElementsByTagNameNS: function () { return []; }
      };
    }

    var inertBody = makeInertNode('body');
    Object.defineProperty(inertBody, 'innerHTML', {
      get: function () { return this._html || ''; },
      set: function (v) { this._html = String(v); this.childNodes = []; this.firstChild = null; }
    });

    var inertDoc = {
      nodeType: 9,
      nodeName: '#document',
      documentElement: makeInertNode('html'),
      body: inertBody,
      head: makeInertNode('head'),
      createElement: function (name) { return makeInertNode(name); },
      createElementNS: function (ns, name) { return makeInertNode(name, ns); },
      createTextNode: function (text) { return { nodeType: 3, nodeName: '#text', data: String(text || ''), textContent: String(text || ''), parentNode: null }; },
      createComment: function (text) { return { nodeType: 8, nodeName: '#comment', data: String(text || ''), parentNode: null }; },
      createDocumentFragment: function () { return { nodeType: 11, nodeName: '#document-fragment', childNodes: [], appendChild: function (n) { this.childNodes.push(n); return n; } }; },
      importNode: function (node) { return node; },
      querySelectorAll: function () { return []; },
      getElementsByTagName: function () { return []; },
      getElementsByTagNameNS: function () { return []; },
      implementation: {
        createHTMLDocument: function () {
          var d = {
            nodeType: 9,
            documentElement: makeInertNode('html'),
            body: makeInertNode('body'),
            head: makeInertNode('head'),
            createElement: inertDoc.createElement,
            createElementNS: inertDoc.createElementNS,
            createTextNode: inertDoc.createTextNode,
            createComment: inertDoc.createComment,
            createDocumentFragment: inertDoc.createDocumentFragment,
            importNode: inertDoc.importNode,
            querySelectorAll: function () { return []; },
            getElementsByTagName: function () { return []; },
            getElementsByTagNameNS: function () { return []; }
          };
          Object.defineProperty(d.body, 'innerHTML', {
            get: function () { return this._html || ''; },
            set: function (v) { this._html = String(v); this.childNodes = []; this.firstChild = null; }
          });
          return d;
        },
        createDocument: function () {
          return this.createHTMLDocument('');
        }
      }
    };

    var fakeWindow = {
      document: inertDoc,
      navigator: { userAgent: 'node' },
      location: { href: 'https://example.test/' },
      Node: function Node() {},
      Element: function Element() {},
      DocumentFragment: function DocumentFragment() {},
      Document: function Document() {},
      HTMLTemplateElement: function HTMLTemplateElement() {},
      namedNodeMap: function namedNodeMap() {},
      setTimeout: function (fn) { if (typeof fn === 'function') fn(); return 0; },
      clearTimeout: function () {}
    };
    fakeWindow.Node.prototype = {};
    fakeWindow.Element.prototype = Object.create(fakeWindow.Node.prototype);
    fakeWindow.DocumentFragment.prototype = Object.create(fakeWindow.Node.prototype);
    fakeWindow.Document.prototype = Object.create(fakeWindow.Node.prototype);
    fakeWindow.HTMLTemplateElement.prototype = Object.create(fakeWindow.Element.prototype);

    var purify = createDOMPurify(fakeWindow);
    if (!purify || typeof purify.sanitize !== 'function') {
      throw new Error('failed to initialize DOMPurify');
    }

    var benignInput = 'plain text';
    var benignOut = purify.sanitize(benignInput);
    if (typeof benignOut !== 'string') {
      throw new Error('benign sanitize did not return string');
    }

    operation_completed = true;

    var maliciousInput = '<img src=x onerror=alert(1)><svg><g/onload=alert(2)//<p><a href="javascript:alert(3)">x</a>';
    var maliciousOut = String(purify.sanitize(maliciousInput));

    var hasOnerror = /onerror\s*=/i.test(maliciousOut);
    var hasOnload = /onload\s*=/i.test(maliciousOut);
    var hasJsScheme = /javascript\s*:/i.test(maliciousOut);

    exploit_succeeded = hasOnerror || hasOnload || hasJsScheme;
    evidence = 'benign=' + benignOut.length + ';mal=' + maliciousOut.length + ';onerror=' + hasOnerror + ';onload=' + hasOnload + ';js=' + hasJsScheme;
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