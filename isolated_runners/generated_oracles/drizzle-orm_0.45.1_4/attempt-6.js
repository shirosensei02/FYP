let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  const sqlite = require('drizzle-orm/sqlite-core');

  if (!orm || typeof orm.sql !== 'function') throw new Error('missing_sql');
  if (!sqlite || typeof sqlite.sqliteTable !== 'function' || typeof sqlite.text !== 'function') throw new Error('missing_sqlite_core');

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

  const marker = 'drizzle_ident_marker_a19f2d';
  const payload = `x";select'${marker}'as p;--`;
  const evil = sqliteTable(payload, { c: text('c') });
  const malQuery = sql`select ${evil.c} from ${evil}`;
  const malBuilt = malQuery.toQuery(config);
  const malSql = String((malBuilt && malBuilt.sql) || '');

  const hasMarkerOutsideIdentifier = malSql.includes(`'${marker}'`);
  const hasSemicolonOutsideQuotes = /;\s*select/i.test(malSql);

  const expectedEscapedIdent = `"x"";select'${marker}'as p;--"`;
  const fullyEscaped = malSql.includes(expectedEscapedIdent);

  exploit_succeeded = hasMarkerOutsideIdentifier || hasSemicolonOutsideQuotes || !fullyEscaped;
  evidence = JSON.stringify({ benignSql, malSql, hasMarkerOutsideIdentifier, hasSemicolonOutsideQuotes, fullyEscaped });
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

out();