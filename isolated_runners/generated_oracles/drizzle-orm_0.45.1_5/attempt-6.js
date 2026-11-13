let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  const sqliteCore = require('drizzle-orm/sqlite-core');

  if (!orm || typeof orm.sql !== 'function') {
    throw new Error('drizzle sql tag unavailable');
  }
  if (!sqliteCore || typeof sqliteCore.sqliteTable !== 'function' || typeof sqliteCore.text !== 'function') {
    throw new Error('sqlite-core APIs unavailable');
  }

  const users = sqliteCore.sqliteTable('users', { name: sqliteCore.text('name') });

  const benignQ = orm.sql`select ${users.name} from ${users}`;
  const benignStr = typeof benignQ?.toQuery === 'function' ? benignQ.toQuery({ escapeName: (n) => `"${String(n).replace(/"/g, '""')}"`, escapeParam: () => '?', escapeString: (s) => `'${String(s).replace(/'/g, "''")}'` }).sql : String(benignQ);

  if (!/select/i.test(benignStr) || !/from/i.test(benignStr)) {
    throw new Error('benign operation did not produce expected SQL');
  }

  operation_completed = true;

  const payload = 'col";DROP TABLE secrets;--';
  let malSql;
  try {
    const malQ = orm.sql`select * from users order by ${orm.sql.identifier(payload)}`;
    malSql = typeof malQ?.toQuery === 'function'
      ? malQ.toQuery({ escapeName: (n) => `"${String(n).replace(/"/g, '""')}"`, escapeParam: () => '?', escapeString: (s) => `'${String(s).replace(/'/g, "''")}'` }).sql
      : String(malQ);
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'blocked_by_exception:' + (err && err.message ? err.message : String(err));
    finish();
    return;
  }

  const hasStatementBreakout = /;\s*drop\s+table/i.test(malSql);
  const hasCommentTail = /--/.test(malSql);
  exploit_succeeded = hasStatementBreakout && hasCommentTail;
  evidence = 'benign_sql=' + JSON.stringify(benignStr) + '; malicious_sql=' + JSON.stringify(malSql) + '; breakout=' + hasStatementBreakout + '; comment=' + hasCommentTail;
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (e && e.message ? e.message : String(e));
}

finish();