let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  const sqlite = require('drizzle-orm/sqlite-core');

  if (!orm || typeof orm.sql !== 'function') throw new Error('missing_sql_tag');
  if (!sqlite || typeof sqlite.sqliteTable !== 'function' || typeof sqlite.text !== 'function') throw new Error('missing_sqlite_core_api');

  const { sql } = orm;
  const { sqliteTable, text } = sqlite;

  const config = {
    escapeName: (n) => `"${String(n).replace(/"/g, '""')}"`,
    escapeParam: () => '?',
    escapeString: (s) => `'${String(s).replace(/'/g, "''")}'`,
    casing: { getColumnCasing: (c) => c.name },
    paramStartIndex: { value: 0 },
    inlineParams: false,
  };

  const users = sqliteTable('users', { id: text('id') });
  const benignQuery = sql`select ${users.id} from ${users}`;
  if (!benignQuery || typeof benignQuery.toQuery !== 'function') throw new Error('benign_toQuery_missing');

  const benignBuilt = benignQuery.toQuery(config);
  const benignSql = String((benignBuilt && benignBuilt.sql) || '');
  if (!/select\s+"users"\."id"\s+from\s+"users"/i.test(benignSql)) {
    throw new Error('benign_sql_unexpected:' + benignSql);
  }

  operation_completed = true;

  const marker = 'drizzle_ident_marker_7b1c5a';
  const payload = `x"; select '${marker}' as p; --`;
  const evil = sqliteTable(payload, { c: text('c') });
  const maliciousQuery = sql`select ${evil.c} from ${evil}`;
  const malBuilt = maliciousQuery.toQuery(config);
  const malSql = String((malBuilt && malBuilt.sql) || '');

  const inSingleQuotedLiteral = new RegExp("'" + marker + "'").test(malSql);
  const hasSecondStatement = /;\s*select\s+/i.test(malSql);
  const hasComment = /--/.test(malSql);

  exploit_succeeded = inSingleQuotedLiteral || hasSecondStatement || hasComment;
  evidence = JSON.stringify({ benignSql, malSql, inSingleQuotedLiteral, hasSecondStatement, hasComment });
} catch (err) {
  const msg = err && err.message ? err.message : String(err);
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error:' + msg;
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_or_error:' + msg;
  }
}

finish();