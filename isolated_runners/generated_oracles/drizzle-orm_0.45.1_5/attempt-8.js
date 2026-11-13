let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');

  if (!orm || typeof orm.sql !== 'function' || typeof orm.sql.identifier !== 'function') {
    throw new Error('drizzle-orm sql APIs unavailable');
  }

  const dialect = {
    escapeName: (name) => '"' + String(name).replace(/"/g, '""') + '"',
    escapeParam: () => '?',
    escapeString: (str) => "'" + String(str).replace(/'/g, "''") + "'",
    casing: { getColumnCasing: (col) => (col && typeof col.name === 'string' ? col.name : String(col)) }
  };

  const benignIdentifier = ['safe_table'];
  const benignQuery = orm.sql`select * from ${orm.sql.identifier(benignIdentifier)}`;
  const benignSql = benignQuery.toQuery(dialect).sql;

  if (!/from\s+"safe_table"/i.test(benignSql)) {
    throw new Error('benign query did not render expected identifier: ' + benignSql);
  }

  operation_completed = true;

  const payloadParts = ['safe_table";DROP TABLE secrets;--'];
  let maliciousSql;
  try {
    const maliciousQuery = orm.sql`select * from ${orm.sql.identifier(payloadParts)}`;
    maliciousSql = maliciousQuery.toQuery(dialect).sql;
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'blocked_by_exception:' + (e && e.message ? e.message : String(e));
    finish();
    return;
  }

  const hasRawDrop = /drop\s+table\s+secrets/i.test(maliciousSql);
  const hasComment = /--/.test(maliciousSql);
  const hasSemicolon = /;/.test(maliciousSql);

  exploit_succeeded = hasRawDrop && hasComment && hasSemicolon;
  evidence = 'benign_sql=' + JSON.stringify(benignSql) + '; malicious_sql=' + JSON.stringify(maliciousSql) + '; hasRawDrop=' + hasRawDrop + '; hasComment=' + hasComment + '; hasSemicolon=' + hasSemicolon;
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (e && e.message ? e.message : String(e));
}

finish();