let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const { sql } = require('drizzle-orm');

  const benignName = 'safe_col';
  const benignFrag = sql.identifier(benignName);
  const benignSqlObj = benignFrag.getSQL();
  const benignBuilt = benignSqlObj.toQuery({
    escapeName: (name) => '"' + String(name) + '"',
    escapeParam: () => '?',
    escapeString: (str) => "'" + String(str).replace(/'/g, "''") + "'",
    prepareTyping: () => 'none',
    casing: undefined,
    paramStartIndex: { value: 0 },
    inlineParams: false,
  });

  if (!benignBuilt || typeof benignBuilt.sql !== 'string') {
    throw new Error('benign build did not produce SQL text');
  }
  if (benignBuilt.sql !== '"safe_col"') {
    throw new Error('benign identifier quoting was not as expected');
  }

  operation_completed = true;

  const payload = 'x";select 1--';
  try {
    const malFrag = sql.identifier(payload);
    const malBuilt = malFrag.getSQL().toQuery({
      escapeName: (name) => '"' + String(name) + '"',
      escapeParam: () => '?',
      escapeString: (str) => "'" + String(str).replace(/'/g, "''") + "'",
      prepareTyping: () => 'none',
      casing: undefined,
      paramStartIndex: { value: 0 },
      inlineParams: false,
    });

    const malSql = malBuilt && typeof malBuilt.sql === 'string' ? malBuilt.sql : '';
    const expectedSafe = '"x"";select 1--"';
    exploit_succeeded = malSql !== expectedSafe;
    evidence = JSON.stringify({ benign_sql: benignBuilt.sql, malicious_sql: malSql, expected_safe: expectedSafe });
  } catch (err) {
    exploit_succeeded = false;
    evidence = JSON.stringify({ blocked: true, error_type: err && err.name ? err.name : 'Error' });
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (e && e.message ? e.message : String(e));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));