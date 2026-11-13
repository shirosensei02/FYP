let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const { sql } = require('drizzle-orm');
  const { PgDialect } = require('drizzle-orm/pg-core');

  const dialect = new PgDialect();

  // Benign operation first: prove public API path works end-to-end.
  const benign = sql.identifier('safe_col').getSQL().toQuery({
    casing: undefined,
    escapeName: (name) => dialect.escapeName(name),
    escapeParam: (num) => `$${num + 1}`,
    escapeString: (str) => `'${String(str).replace(/'/g, "''")}'`,
    prepareTyping: () => 'none',
    paramStartIndex: { value: 0 },
    inlineParams: false,
  });

  if (!benign || typeof benign.sql !== 'string' || benign.sql !== '"safe_col"') {
    throw new Error('benign identifier rendering failed');
  }

  operation_completed = true;

  // Malicious identifier containing a quote delimiter.
  const payload = 'x";select 1--';
  try {
    const malicious = sql.identifier(payload).getSQL().toQuery({
      casing: undefined,
      escapeName: (name) => dialect.escapeName(name),
      escapeParam: (num) => `$${num + 1}`,
      escapeString: (str) => `'${String(str).replace(/'/g, "''")}'`,
      prepareTyping: () => 'none',
      paramStartIndex: { value: 0 },
      inlineParams: false,
    });

    const malSql = malicious && typeof malicious.sql === 'string' ? malicious.sql : '';
    const expectedSafe = '"x"";select 1--"';

    // Vulnerable: delimiter not doubled -> output differs from expected safe quoting.
    exploit_succeeded = malSql !== expectedSafe;
    evidence = JSON.stringify({ benign_sql: benign.sql, malicious_sql: malSql, expected_safe: expectedSafe });
  } catch (err) {
    // Patched implementations may throw; that is blocked after benign success.
    exploit_succeeded = false;
    evidence = JSON.stringify({ blocked: true, error_type: err && err.name ? err.name : 'Error' });
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));