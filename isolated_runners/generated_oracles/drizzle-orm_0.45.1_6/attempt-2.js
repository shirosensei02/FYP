let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const { sql } = require('drizzle-orm');

  const benignInput = 'safe_col';
  const benignNode = sql.identifier(benignInput);
  const benignRendered = String(benignNode);

  if (typeof benignRendered !== 'string' || benignRendered.length === 0) {
    throw new Error('benign identifier rendering failed');
  }

  operation_completed = true;

  const payload = 'x" DESC; DROP TABLE users; --';
  let maliciousRendered;
  let maliciousThrew = false;
  try {
    maliciousRendered = String(sql.identifier(payload));
  } catch (e) {
    maliciousThrew = true;
    maliciousRendered = '';
  }

  if (maliciousThrew) {
    exploit_succeeded = false;
    evidence = JSON.stringify({
      benignRendered,
      payload,
      blockedByException: true
    });
  } else {
    const containsRawQuotePayload = maliciousRendered.includes(payload);
    const containsInjectedClause = maliciousRendered.includes('DESC; DROP TABLE users; --');
    const hasEscapedDoubleQuote = maliciousRendered.includes('""');

    exploit_succeeded = containsRawQuotePayload || (containsInjectedClause && !hasEscapedDoubleQuote);
    evidence = JSON.stringify({
      benignRendered,
      maliciousRendered,
      containsRawQuotePayload,
      containsInjectedClause,
      hasEscapedDoubleQuote
    });
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));