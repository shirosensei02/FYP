let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function done() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');

  if (!orm || typeof orm.sql !== 'function' || typeof orm.sql.identifier !== 'function') {
    throw new Error('required drizzle-orm sql APIs unavailable');
  }

  const dialect = {
    escapeName: (name) => '"' + String(name).replace(/"/g, '""') + '"',
    escapeParam: () => '?',
    escapeString: (str) => "'" + String(str).replace(/'/g, "''") + "'",
    casing: { getColumnCasing: (col) => (col && typeof col.name === 'string' ? col.name : String(col)) }
  };

  const benignQuery = orm.sql`select ${orm.sql.identifier('safe_column')} from ${orm.sql.identifier('safe_table')}`;
  const benignSql = benignQuery.toQuery(dialect).sql;
  if (!/select\s+"safe_column"\s+from\s+"safe_table"/i.test(benignSql)) {
    throw new Error('benign sql generation failed: ' + benignSql);
  }

  operation_completed = true;

  const payload = 'x";DROP TABLE secrets;--';
  let maliciousSql;
  try {
    const maliciousQuery = orm.sql`select ${orm.sql.identifier('safe_column')} from ${orm.sql.identifier('safe_table')} order by ${orm.sql.identifier(payload)}`;
    maliciousSql = maliciousQuery.toQuery(dialect).sql;
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'blocked_by_exception:' + (err && err.message ? err.message : String(err));
    done();
    return;
  }

  const breakout = /;\s*drop\s+table\s+secrets/i.test(maliciousSql);
  const comment = /--/.test(maliciousSql);
  exploit_succeeded = breakout && comment;
  evidence = 'benign_sql=' + JSON.stringify(benignSql) + '; malicious_sql=' + JSON.stringify(maliciousSql) + '; breakout=' + breakout + '; comment=' + comment;
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (err && err.message ? err.message : String(err));
}

done();