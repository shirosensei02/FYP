let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const core = require('drizzle-orm/sqlite-core');
  const orm = require('drizzle-orm');

  if (!core || !orm || typeof core.sqliteTable !== 'function' || typeof core.text !== 'function' || typeof orm.sql !== 'function') {
    throw new Error('required_api_missing');
  }

  const sqliteTable = core.sqliteTable;
  const text = core.text;
  const sql = orm.sql;

  const benignTable = sqliteTable('users', { id: text('id') });
  const benignQuery = sql`select ${benignTable.id} from ${benignTable}`;

  if (!benignQuery || typeof benignQuery.toSQL !== 'function') {
    throw new Error('benign_query_builder_missing_toSQL');
  }

  const benignBuilt = benignQuery.toSQL();
  const benignSql = String((benignBuilt && benignBuilt.sql) || '');

  if (!/from\s+"users"/i.test(benignSql) || !/"users"\."id"/i.test(benignSql)) {
    throw new Error('benign_sql_unexpected:' + benignSql);
  }

  operation_completed = true;

  const marker = 'DRIZZLE_IDENT_INJECT_MARKER_9f1a';
  const payloadName = `evil"; select '${marker}' as p; --`;
  const evilTable = sqliteTable(payloadName, { c: text('c') });
  const malQuery = sql`select ${evilTable.c} from ${evilTable}`;
  const malBuilt = malQuery.toSQL();
  const malSql = String((malBuilt && malBuilt.sql) || '');

  const hasMarker = malSql.includes(marker);
  const hasInjectedSelect = /;\s*select\s+/i.test(malSql);
  const hasInlineComment = /--/.test(malSql);

  exploit_succeeded = hasMarker || hasInjectedSelect || hasInlineComment;
  evidence = JSON.stringify({ benignSql, malSql, hasMarker, hasInjectedSelect, hasInlineComment });
} catch (err) {
  const msg = err && err.message ? err.message : String(err);
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error:' + msg;
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_blocked:' + msg;
  }
}

emit();