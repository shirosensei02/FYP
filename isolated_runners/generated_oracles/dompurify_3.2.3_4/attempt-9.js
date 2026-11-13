let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function done() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');

  function makeMinimalWindow() {
    const doc = {
      nodeType: 9,
      documentElement: { nodeName: 'HTML', namespaceURI: 'http://www.w3.org/1999/xhtml' },
      body: { innerHTML: '' },
      implementation: {
        createHTMLDocument: function () {
          return {
            body: { innerHTML: '' },
            documentElement: { nodeName: 'HTML', namespaceURI: 'http://www.w3.org/1999/xhtml' }
          };
        }
      },
      createElement: function () {
        return {
          nodeType: 1,
          nodeName: 'DIV',
          namespaceURI: 'http://www.w3.org/1999/xhtml',
          attributes: [],
          childNodes: [],
          setAttribute: function () {},
          removeAttribute: function () {},
          appendChild: function () {},
          cloneNode: function () { return this; },
          innerHTML: ''
        };
      },
      createElementNS: function (_ns, name) {
        return {
          nodeType: 1,
          nodeName: String(name || 'DIV').toUpperCase(),
          namespaceURI: _ns || 'http://www.w3.org/1999/xhtml',
          attributes: [],
          childNodes: [],
          setAttribute: function () {},
          removeAttribute: function () {},
          appendChild: function () {},
          cloneNode: function () { return this; },
          innerHTML: ''
        };
      },
      createTextNode: function (t) { return { nodeType: 3, data: String(t || '') }; },
      createComment: function (t) { return { nodeType: 8, data: String(t || '') }; }
    };

    const win = {
      window: null,
      self: null,
      top: null,
      navigator: { userAgent: 'node' },
      document: doc,
      Element: function Element() {},
      HTMLElement: function HTMLElement() {},
      HTMLTemplateElement: function HTMLTemplateElement() {},
      Node: function Node() {},
      DocumentFragment: function DocumentFragment() {},
      addEventListener: function () {},
      removeEventListener: function () {}
    };
    win.window = win;
    win.self = win;
    win.top = win;
    return win;
  }

  const DOMPurify = createDOMPurify(makeMinimalWindow());
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('sanitize API unavailable');
  }

  let benign;
  try {
    benign = String(DOMPurify.sanitize('<b>ok</b>'));
  } catch (e) {
    evidence = 'benign operation threw: ' + (e && e.message ? e.message : String(e));
    done();
    return;
  }

  if (!/ok/.test(benign)) {
    evidence = 'benign operation produced unexpected output: ' + JSON.stringify(benign);
    done();
    return;
  }

  operation_completed = true;

  const payload = '<math><mi//xlink:href="data:x,<script>alert(1)</script>">X</mi></math>';
  try {
    const out = String(DOMPurify.sanitize(payload));
    const keptScriptTag = /<script/i.test(out);
    const keptXlinkHref = /xlink:href\s*=\s*/i.test(out);
    const keptDataScript = /data:x\s*,\s*<script/i.test(out);
    exploit_succeeded = keptScriptTag || (keptXlinkHref && keptDataScript);
    evidence = 'malicious_out=' + JSON.stringify(out) + ';keptScriptTag=' + keptScriptTag + ';keptXlinkHref=' + keptXlinkHref + ';keptDataScript=' + keptDataScript;
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious call threw after benign success: ' + (e && e.message ? e.message : String(e));
  }

  done();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/module error: ' + (e && e.message ? e.message : String(e));
  done();
}
