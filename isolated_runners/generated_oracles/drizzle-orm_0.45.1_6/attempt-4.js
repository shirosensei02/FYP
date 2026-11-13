let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const { sql } = require('drizzle-orm');

  function flatten(chunk) {
    if (chunk == null) return '';
    if (typeof chunk === 'string') return chunk;
    if (typeof chunk === 'number' || typeof chunk === 'boolean') return String(chunk);
    if (Array.isArray(chunk)) return chunk.map(flatten).join('');
    if (typeof chunk === 'object') {
      if (typeof chunk.sql === 'string') return chunk.sql;
      if (Array.isArray(chunk.queryChunks)) return chunk.queryChunks.map(flatten).join('');
      if (typeof chunk.value === 'string') return chunk.value;
      if (Array.isArray(chunk.path)) return chunk.path.map((p) => String(p)).join('.');
      try { return String(chunk); } catch (_) { return '[object]'; }
    }
    return String(chunk);
  }

  function render(fragment) {
    if (!fragment || typeof fragment !== 'object') return String(fragment);
    if (Array.isArray(fragment.queryChunks)) return fragment.queryChunks.map(flatten).join('');
    return flatten(fragment);
  }

  const benign = 'safe_col';
  const benignFrag = sql`${sql.identifier(benign)}`;
  const benignSql = render(benignFrag);

  const benignLooksQuoted = benignSql === '"safe_col"' || benignSql === '`safe_col`';
  if (!benignLooksQuoted) {
    throw new Error('benign identifier rendering unexpected');
  }

  operation_completed = true;

  const payload = 'x";select 1--';
  let maliciousSql = '';
  try {
    maliciousSql = render(sql`${sql.identifier(payload)}`);
    const vulnerablePgStyle = maliciousSql === '"x";select 1--"';
    const vulnerableMyStyle = maliciousSql === '`x";select 1--`';
    exploit_succeeded = vulnerablePgStyle || vulnerableMyStyle;
    evidence = JSON.stringify({ benignSql, maliciousSql, vulnerablePgStyle, vulnerableMyStyle });
  } catch (e) {
    exploit_succeeded = false;
    evidence = JSON.stringify({ benignSql, blocked: true, errorType: e && e.name ? e.name : 'Error' });
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (e && e.message ? e.message : String(e));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));