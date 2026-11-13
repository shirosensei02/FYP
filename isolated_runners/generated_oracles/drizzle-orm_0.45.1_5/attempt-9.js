let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  if (!orm || typeof orm.sql !== 'function' || typeof orm.sql.identifier !== 'function') {
    throw new Error('drizzle-orm sql or sql.identifier unavailable');
  }

  const dialect = {
    escapeName: (name) => '"' + String(name).replace(/"/g, '""') + '"',
    escapeParam: () => '?',
    escapeString: (str) => "'" + String(str).replace(/'/g, "''") + "'",
    casing: { getColumnCasing: (col) => (col && typeof col.name === 'string' ? col.name : String(col)) }
  };

  const benign = orm.sql`select * from ${orm.sql.identifier(['safe_table'])}`;
  const benignSql = benign.toQuery(dialect).sql;
  if (!/from\s+"safe_table"/i.test(benignSql)) {
    throw new Error('benign identifier rendering unexpected: ' + benignSql);
  }

  operation_completed = true;

  const payload = 'x";DROP TABLE secrets;--';
  let maliciousSql;
  try {
    const malicious = orm.sql`select * from ${orm.sql.identifier([payload])}`;
    maliciousSql = malicious.toQuery(dialect).sql;
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'blocked_by_exception:' + (e && e.message ? e.message : String(e));
    finish();
    return;
  }

  const expectedEscaped = '"x"";DROP TABLE secrets;--"';
  const containsExpectedEscaped = maliciousSql.includes(expectedEscaped);
  const containsRawBreakout = maliciousSql.includes('";DROP TABLE secrets;--');

  exploit_succeeded = containsRawBreakout;
  evidence = 'benign_sql=' + JSON.stringify(benignSql)
    + '; malicious_sql=' + JSON.stringify(maliciousSql)
    + '; containsExpectedEscaped=' + containsExpectedEscaped
    + '; containsRawBreakout=' + containsRawBreakout;
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (e && e.message ? e.message : String(e));
}

finish();