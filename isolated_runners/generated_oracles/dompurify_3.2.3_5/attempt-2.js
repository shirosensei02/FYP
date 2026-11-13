const fs = require('node:fs');
const path = require('node:path');

(function () {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = path.join('/tmp', 'oracle-dompurify-' + Date.now() + '-' + Math.random().toString(16).slice(2));
    fs.mkdirSync(marker, { recursive: true });

    // Use DOMPurify's non-DOM helper API to avoid requiring a browser/jsdom environment.
    const DOMPurify = require('dompurify');

    if (!DOMPurify || typeof DOMPurify.isValidAttribute !== 'function') {
      throw new Error('dompurify export missing isValidAttribute API');
    }

    // Benign operation first: ordinary safe URL should be accepted.
    const benignOk = DOMPurify.isValidAttribute('a', 'href', 'https://example.com/path?q=1');
    if (benignOk !== true) {
      throw new Error('benign attribute validation failed');
    }

    operation_completed = true;

    // Malicious probe: javascript: URL in href should be rejected.
    const maliciousOk = DOMPurify.isValidAttribute('a', 'href', 'javascript:alert(1)');

    // If malicious value is accepted, treat as vulnerability reproduction.
    exploit_succeeded = maliciousOk === true;
    evidence = 'benign_ok=' + benignOk + ';malicious_ok=' + maliciousOk + ';marker=' + marker;
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'exception:' + (err && err.message ? err.message : String(err));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed,
    exploit_succeeded,
    evidence
  }));
})();
