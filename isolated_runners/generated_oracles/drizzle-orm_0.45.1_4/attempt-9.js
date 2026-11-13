let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  const sqlite = require('drizzle-orm/sqlite-core');

  if (!orm || typeof orm.sql !== 'function') throw new Error('missing_drizzle_sql');
  if (!sqlite || typeof sqlite.sqliteTable !== 'function' || typeof sqlite.text !== 'function') {
    throw new Error('missing_sqlite_core_api');
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
  if (!/^select\s+"users"\."id"\s+from\s+"users"$/i.test(benignSql.trim())) {
    throw new Error('benign_sql_unexpected:' + benignSql);
  }

  operation_completed = true;

  const marker = '__drizzle_ident_oracle_9c2d1a__';
  const payload = `x";select '${marker}' as p;--`;
  const evilTable = sqliteTable(payload, { c: text('c') });
  const malQuery = sql`select ${evilTable.c} from ${evilTable}`;
  const malSql = String((malQuery.toQuery(cfg) || {}).sql || '');

  const normalized = malSql.replace(/\s+/g, ' ').toLowerCase();
  const hasInjectedSelect = normalized.includes(`;select '${marker.toLowerCase()}' as p;--`.toLowerCase());

  const firstFrom = normalized.indexOf(' from ');
  const selectClause = firstFrom >= 0 ? normalized.slice(0, firstFrom) : normalized;
  const semicolonsInSelectClause = (selectClause.match(/;/g) || []).length;

  exploit_succeeded = hasInjectedSelect || semicolonsInSelectClause > 0;
  evidence = JSON.stringify({ benignSql, malSql, hasInjectedSelect, semicolonsInSelectClause });
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