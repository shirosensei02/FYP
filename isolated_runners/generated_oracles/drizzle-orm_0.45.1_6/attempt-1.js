const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const { sql } = require('drizzle-orm');

  // Benign call must succeed first
  const benign = sql`select * from t order by ${sql.identifier('safe_col')}`;
  const benignText = String(benign && benign.queryChunks ? benign.queryChunks.map((c) => (typeof c === 'string' ? c : c && c.value ? c.value : '')).join('') : benign);

  if (!benign || typeof benign !== 'object') {
    throw new Error('benign identifier construction did not return expected object');
  }

  operation_completed = true;

  // Malicious identifier containing quote delimiter intended to break out
  const payload = 'x" DESC; DROP TABLE users; --';
  const malicious = sql`select * from t order by ${sql.identifier(payload)}`;

  const rendered = String(malicious && malicious.queryChunks ? malicious.queryChunks.map((c) => {
    if (typeof c === 'string') return c;
    if (c && typeof c === 'object') {
      if (typeof c.value === 'string') return c.value;
      if (typeof c.sql === 'string') return c.sql;
      if (typeof c.text === 'string') return c.text;
    }
    return '';
  }).join('') : malicious);

  const hasInjectedSequence = rendered.includes('DESC; DROP TABLE users; --');
  const quoteEscaped = rendered.includes('""');

  exploit_succeeded = hasInjectedSequence && !quoteEscaped;
  evidence = JSON.stringify({ benign_preview: benignText.slice(0, 120), malicious_preview: rendered.slice(0, 220), hasInjectedSequence, quoteEscaped });
} catch (err) {
  if (!operation_completed) {
    evidence = 'setup_or_benign_error:' + (err && err.message ? err.message : String(err));
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_blocked:' + (err && err.message ? err.message : String(err));
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
