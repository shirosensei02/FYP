let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  const pgCore = require('drizzle-orm/pg-core');

  if (!orm || typeof orm.sql !== 'function') throw new Error('missing sql tag');
  if (!pgCore || typeof pgCore.pgTable !== 'function' || typeof pgCore.text !== 'function') {
    throw new Error('missing pg-core table builders');
  }

  const users = pgCore.pgTable('users', { name: pgCore.text('name') });
  const benign = orm.sql`select ${users.name} from ${users}`;

  const benignSqlObj = benign.toQuery({
    casing: { getColumnCasing: (col) => col.name },
    escapeName: (n) => '"' + String(n).replace(/"/g, '""') + '"',
    escapeParam: (i) => '$' + i,
    escapeString: (s) => "'" + String(s).replace(/'/g, "''") + "'",
    inlineParams: false,
    paramStartIndex: { value: 0 },
  });

  if (!benignSqlObj || typeof benignSqlObj.sql !== 'string' || benignSqlObj.sql.indexOf('users') === -1) {
    throw new Error('benign sql generation failed');
  }

  operation_completed = true;

  const payload = 'evil";DROP TABLE secrets;--';
  const inj = pgCore.pgTable('items', {
    safe: pgCore.text(payload),
  });

  const malicious = orm.sql`select ${inj.safe} from ${inj}`;
  const malSqlObj = malicious.toQuery({
    casing: { getColumnCasing: (col) => col.name },
    escapeName: (n) => '"' + String(n).replace(/"/g, '""') + '"',
    escapeParam: (i) => '$' + i,
    escapeString: (s) => "'" + String(s).replace(/'/g, "''") + "'",
    inlineParams: false,
    paramStartIndex: { value: 0 },
  });

  const malSql = malSqlObj && typeof malSqlObj.sql === 'string' ? malSqlObj.sql : String(malSqlObj);
  const hasUnescapedBreakout = /";\s*drop\s+table\s+secrets;--/i.test(malSql);
  const hasEscapedQuotes = malSql.includes('"";DROP TABLE secrets;--');

  exploit_succeeded = hasUnescapedBreakout || !hasEscapedQuotes;
  evidence = 'benign=' + JSON.stringify(benignSqlObj.sql) + ' malicious=' + JSON.stringify(malSql) + ' hasUnescapedBreakout=' + hasUnescapedBreakout + ' hasEscapedQuotes=' + hasEscapedQuotes;
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

finish();