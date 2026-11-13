let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  const pgCore = require('drizzle-orm/pg-core');

  if (!orm || typeof orm.sql !== 'function') throw new Error('drizzle sql tag unavailable');
  if (!pgCore || typeof pgCore.pgTable !== 'function' || typeof pgCore.text !== 'function') {
    throw new Error('pg-core API unavailable');
  }

  const dialect = {
    casing: { getColumnCasing: (col) => col.name },
    escapeName: (n) => '"' + String(n).replace(/"/g, '""') + '"',
    escapeParam: (i) => '$' + i,
    escapeString: (s) => "'" + String(s).replace(/'/g, "''") + "'",
    inlineParams: false,
    paramStartIndex: { value: 0 },
  };

  const benignTable = pgCore.pgTable('users', { name: pgCore.text('name') });
  const benignQuery = orm.sql`select ${benignTable.name} from ${benignTable}`;
  const benignSql = benignQuery.toQuery(dialect).sql;

  if (typeof benignSql !== 'string' || !/select\s+"users"\."name"\s+from\s+"users"/i.test(benignSql)) {
    throw new Error('benign SQL shape mismatch: ' + String(benignSql));
  }

  operation_completed = true;

  const payload = 'x";DROP TABLE secrets;--';
  let maliciousTable;
  let malSql;
  let maliciousErr = null;

  try {
    maliciousTable = pgCore.pgTable('items', { [payload]: pgCore.text(payload) });
    malSql = orm.sql`select ${maliciousTable[payload]} from ${maliciousTable}`.toQuery(dialect).sql;
  } catch (e) {
    maliciousErr = e;
  }

  if (maliciousErr) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_exception:' + (maliciousErr && maliciousErr.message ? maliciousErr.message : String(maliciousErr));
  } else {
    const escapedIdentifier = '"x"";DROP TABLE secrets;--"';
    const hasProperEscaping = typeof malSql === 'string' && malSql.includes(escapedIdentifier);
    const hasRawBreakout = typeof malSql === 'string' && /"x";\s*drop\s+table\s+secrets;--"?/i.test(malSql);
    exploit_succeeded = !hasProperEscaping || hasRawBreakout;
    evidence = 'benign=' + JSON.stringify(benignSql) + ' malicious=' + JSON.stringify(malSql) + ' hasProperEscaping=' + hasProperEscaping + ' hasRawBreakout=' + hasRawBreakout;
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (e && e.message ? e.message : String(e));
}

out();