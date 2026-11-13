let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');

  // Minimal window-like object: enough for factory creation without external deps.
  const fakeWindow = {
    document: {
      nodeType: 9,
      implementation: {
        createHTMLDocument: function () {
          return {
            body: { innerHTML: '' },
            documentElement: { nodeName: 'HTML' }
          };
        }
      }
    },
    navigator: { userAgent: 'node' },
    addEventListener: function () {},
    removeEventListener: function () {}
  };

  const DOMPurify = createDOMPurify(fakeWindow);
  if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
    throw new Error('sanitize API unavailable');
  }

  // Benign operation: default config should preserve plain text.
  let benignOut;
  try {
    benignOut = String(DOMPurify.sanitize('hello-safe-text'));
  } catch (e) {
    evidence = 'benign sanitize threw: ' + (e && e.message ? e.message : String(e));
    finish();
    return;
  }

  if (!/hello-safe-text/.test(benignOut)) {
    evidence = 'benign sanitize unexpected output: ' + JSON.stringify(benignOut);
    finish();
    return;
  }

  operation_completed = true;

  // Malicious case: template-syntax execution sink should be blocked in patched builds.
  const payload = '<p>{{constructor.constructor("return 1337")()}}</p>';
  try {
    const out = String(DOMPurify.sanitize(payload, { SAFE_FOR_TEMPLATES: true }));
    // Vulnerable behavior: template delimiters / executable expression survive.
    const hasTemplateExpr = /\{\{[^}]*constructor\.constructor[^}]*\}\}/i.test(out);
    const hasCtorGadget = /constructor\.constructor\("return 1337"\)\(\)/i.test(out);
    exploit_succeeded = hasTemplateExpr || hasCtorGadget;
    evidence = 'malicious_out=' + JSON.stringify(out) + ';hasTemplateExpr=' + hasTemplateExpr + ';hasCtorGadget=' + hasCtorGadget;
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
