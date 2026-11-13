let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');
  if (typeof createDOMPurify !== 'function') {
    throw new Error('dompurify did not export factory function');
  }

  // Minimal DOM implementation sufficient for string-based sanitize() path.
  const fakeDocument = {
    nodeType: 9,
    implementation: {
      createHTMLDocument: function () {
        return {
          documentElement: { nodeName: 'HTML', namespaceURI: 'http://www.w3.org/1999/xhtml' },
          body: { innerHTML: '' }
        };
      }
    }
  };

  const fakeWindow = {
    document: fakeDocument,
    Node: function Node() {},
    Element: function Element() {},
    DocumentFragment: function DocumentFragment() {},
    HTMLTemplateElement: function HTMLTemplateElement() {}
  };

  const DOMPurify = createDOMPurify(fakeWindow);
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('failed to initialize sanitize()');
  }

  // Benign operation first.
  const benignInput = '<p>Hello <b>world</b></p>';
  let benignOutput;
  try {
    benignOutput = DOMPurify.sanitize(benignInput);
  } catch (e) {
    operation_completed = false;
    evidence = 'benign sanitize threw: ' + (e && e.message ? e.message : String(e));
    finish();
    return;
  }

  if (typeof benignOutput !== 'string' || benignOutput.toLowerCase().indexOf('hello') === -1) {
    operation_completed = false;
    evidence = 'benign sanitize returned unexpected output: ' + JSON.stringify(benignOutput);
    finish();
    return;
  }

  operation_completed = true;

  // Malicious input: SVG/MathML namespace confusion style payload associated with XSS bypass classes.
  const maliciousInput = '<math><annotation-xml encoding="text/html"><svg><script>alert(1)</script></svg></annotation-xml></math>';
  try {
    const maliciousOutput = String(DOMPurify.sanitize(maliciousInput));
    const retainedScript = /<script\b/i.test(maliciousOutput);
    const retainedEventHandler = /on[a-z]+\s*=\s*/i.test(maliciousOutput);
    exploit_succeeded = retainedScript || retainedEventHandler;
    evidence = 'benign=' + JSON.stringify(benignOutput) + '; malicious=' + JSON.stringify(maliciousOutput) + '; retainedScript=' + retainedScript + '; retainedEventHandler=' + retainedEventHandler;
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious sanitize threw after benign success: ' + (e && e.message ? e.message : String(e));
  }

  finish();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/module error: ' + (e && e.message ? e.message : String(e));
  finish();
}