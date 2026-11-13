let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const createDOMPurify = require('dompurify');

  const fakeDocument = {
    nodeType: 9,
    body: { innerHTML: '' },
    documentElement: { nodeName: 'HTML' },
    implementation: {
      createHTMLDocument: function () {
        return {
          body: { innerHTML: '' },
          documentElement: { nodeName: 'HTML' }
        };
      }
    }
  };

  const windowLike = {
    document: fakeDocument,
    navigator: { userAgent: 'node' }
  };
  windowLike.window = windowLike;
  windowLike.self = windowLike;

  const DOMPurify = createDOMPurify(windowLike);

  let benignOut;
  try {
    benignOut = DOMPurify.sanitize('<p>Hello</p>');
  } catch (e) {
    throw new Error('benign sanitize failed: ' + (e && e.message ? e.message : String(e)));
  }

  if (typeof benignOut !== 'string' || benignOut.toLowerCase().indexOf('hello') === -1) {
    throw new Error('benign sanitize failed: unexpected output: ' + String(benignOut));
  }

  operation_completed = true;

  const maliciousInput = '<svg><g/onload=alert(1)></g></svg>';
  let maliciousOut;
  try {
    maliciousOut = DOMPurify.sanitize(maliciousInput, {
      USE_PROFILES: { svg: true, svgFilters: true, html: false }
    });
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (err && err.message ? err.message : String(err));
    emit();
    return;
  }

  const out = String(maliciousOut);
  const hasHandler = /\son[a-z0-9_-]+\s*=\s*/i.test(out);
  exploit_succeeded = hasHandler;
  evidence = JSON.stringify({ benignOut: String(benignOut), maliciousOut: out, hasHandler: hasHandler });
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

emit();