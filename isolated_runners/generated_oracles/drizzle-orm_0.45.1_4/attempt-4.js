let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  const sqlite = require('drizzle-orm/sqlite-core');

  if (!orm || typeof orm.sql !== 'function' || !sqlite || typeof sqlite.sqliteTable !== 'function' || typeof sqlite.text !== 'function') {
    throw new Error('required_api_missing');
  }

  const { sql } = orm;
  const { sqliteTable, text } = sqlite;

  // Benign operation: construct SQL with safe identifier and render via SQL object's API.
  const users = sqliteTable('users', { id: text('id') });
  const benign = sql`select ${users.id} from ${users}`;

  if (!benign || typeof benign.toQuery !== 'function') {
    throw new Error('benign_missing_toQuery');
  }

  const noopEscape = (v) => String(v);
  const benignBuilt = benign.toQuery({
    escapeName: (n) => `"${String(n).replace(/"/g, '""')}"`,
    escapeParam: () => '?',
    escapeString: (s) => `'${String(s).replace(/'/g, "''")}'`,
    casing: { getColumnCasing: (c) => c.name },
    paramStartIndex: { value: 0 },
    inlineParams: false,
    invokeSource: 'oracle',
  });

  const benignSql = String(benignBuilt && benignBuilt.sql || '');
  if (!/from\s+"users"/i.test(benignSql) || !/"users"\."id"/i.test(benignSql)) {
    throw new Error('benign_sql_unexpected:' + benignSql);
  }

  operation_completed = true;

  const marker = 'DRIZZLE_MARK_2f4c9b';
  const payload = `evil"; select '${marker}' as z; --`;
  const evil = sqliteTable(payload, { c: text('c') });
  const malicious = sql`select ${evil.c} from ${evil}`;

  const malBuilt = malicious.toQuery({
    escapeName: (n) => `"${String(n).replace(/"/g, '""')}"`,
    escapeParam: () => '?',
    escapeString: noopEscape,
    casing: { getColumnCasing: (c) => c.name },
    paramStartIndex: { value: 0 },
    inlineParams: false,
    invokeSource: 'oracle',
  });

  const malSql = String(malBuilt && malBuilt.sql || '');

  const hasMarker = malSql.includes(marker);
  const hasBreakout = /;\s*select\s+/i.test(malSql);
  const hasComment = /--/.test(malSql);

  exploit_succeeded = hasMarker || hasBreakout || hasComment;
  evidence = JSON.stringify({ benignSql, malSql, hasMarker, hasBreakout, hasComment });
} catch (e) {
  const msg = e && e.message ? e.message : String(e);
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error:' + msg;
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_blocked:' + msg;
  }
}

out();