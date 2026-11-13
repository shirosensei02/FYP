let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  if (!orm || typeof orm.sql !== 'function' || typeof orm.sql.identifier !== 'function') {
    throw new Error('required drizzle sql APIs unavailable');
  }

  const dialect = {
    escapeName: (name) => '"' + String(name).replace(/"/g, '""') + '"',
    escapeParam: () => '?',
    escapeString: (str) => "'" + String(str).replace(/'/g, "''") + "'",
    casing: { getColumnCasing: (col) => (col && typeof col.name === 'string' ? col.name : String(col)) }
  };

  const benign = orm.sql`select * from ${orm.sql.identifier(['safe_table'])}`;
  const benignSql = benign.toQuery(dialect).sql;
  if (!/select\s+\*\s+from\s+"safe_table"/i.test(benignSql)) {
    throw new Error('benign query rendering mismatch: ' + benignSql);
  }

  operation_completed = true;

  const payload = 'x";DROP TABLE secrets;--';
  try {
    const malicious = orm.sql`select * from ${orm.sql.identifier(payload)}`;
    const maliciousSql = malicious.toQuery(dialect).sql;

    const hasBreakout = maliciousSql.includes('";DROP TABLE secrets;--');
    const hasProperQuoteDoubling = maliciousSql.includes('x"";DROP TABLE secrets;--');

    exploit_succeeded = hasBreakout;
    evidence = 'benign_sql=' + JSON.stringify(benignSql)
      + '; malicious_sql=' + JSON.stringify(maliciousSql)
      + '; has_breakout=' + hasBreakout
      + '; has_quote_doubling=' + hasProperQuoteDoubling;
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious_call_blocked_exception:' + (e && e.message ? e.message : String(e));
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + (e && e.message ? e.message : String(e));
}

out();