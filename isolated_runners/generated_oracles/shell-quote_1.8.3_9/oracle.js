const shellQuote = require('shell-quote');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const out = {
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  };
  console.log('ORACLE_RESULT ' + JSON.stringify(out));
}

try {
  if (!shellQuote || typeof shellQuote.quote !== 'function') {
    evidence = 'quote export missing';
    finish();
  } else {
    // Benign operation first
    const benign = ['echo', 'hello', { op: '&&' }, 'printf', 'ok'];
    const benignOut = shellQuote.quote(benign);
    if (typeof benignOut !== 'string' || benignOut.length === 0 || benignOut.indexOf('echo') === -1) {
      evidence = 'benign quote failed or unexpected output';
      finish();
    } else {
      operation_completed = true;

      // Malicious input targeting newline in .op
      const malicious = ['safe', { op: '\nINJECT\n' }, 'cmd'];
      try {
        const malOut = shellQuote.quote(malicious);
        if (typeof malOut !== 'string') {
          exploit_succeeded = false;
          evidence = 'malicious call returned non-string';
        } else {
          const hasRawNewline = malOut.indexOf('\n') !== -1;
          exploit_succeeded = hasRawNewline;
          evidence = 'benign_out=' + JSON.stringify(benignOut) + '; malicious_out=' + JSON.stringify(malOut) + '; has_raw_newline=' + hasRawNewline;
        }
      } catch (e) {
        exploit_succeeded = false;
        evidence = 'malicious input blocked with exception: ' + (e && e.message ? e.message : String(e));
      }

      finish();
    }
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/benign exception: ' + (e && e.message ? e.message : String(e));
  finish();
}
