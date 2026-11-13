let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const { sql } = require('drizzle-orm');

  function compileToSql(fragment) {
    const out = [];
    if (fragment && typeof fragment === 'object' && Array.isArray(fragment.queryChunks)) {
      for (const ch of fragment.queryChunks) {
        if (typeof ch === 'string') {
          out.push(ch);
        } else if (ch && typeof ch === 'object') {
          if (typeof ch.value === 'string') {
            out.push(ch.value);
          } else if (Array.isArray(ch.path)) {
            out.push(...ch.path.map((p) => String(p)));
          } else {
            out.push(String(ch));
          }
        } else {
          out.push(String(ch));
        }
      }
      return out.join('');
    }
    return String(fragment);
  }

  const benignInput = 'safe_col';
  const benignFrag = sql`select * from t order by ${sql.identifier(benignInput)}`;
  const benignSql = compileToSql(benignFrag);

  if (typeof benignSql !== 'string' || !benignSql.includes('select * from t order by')) {
    throw new Error('benign operation did not produce expected sql text');
  }

  operation_completed = true;

  const payload = 'x" DESC; DROP TABLE users; --';
  let maliciousSql = '';
  let maliciousThrew = false;
  try {
    const maliciousFrag = sql`select * from t order by ${sql.identifier(payload)}`;
    maliciousSql = compileToSql(maliciousFrag);
  } catch (e) {
    maliciousThrew = true;
  }

  if (maliciousThrew) {
    exploit_succeeded = false;
    evidence = JSON.stringify({ blockedByException: true, benignSql });
  } else {
    const hasSemicolon = maliciousSql.includes(';');
    const hasDropTable = maliciousSql.toLowerCase().includes('drop table users');
    const hasComment = maliciousSql.includes('--');
    const hasDoubledQuote = maliciousSql.includes('""');

    exploit_succeeded = hasSemicolon && hasDropTable && hasComment && !hasDoubledQuote;
    evidence = JSON.stringify({ benignSql, maliciousSql, hasSemicolon, hasDropTable, hasComment, hasDoubledQuote });
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));