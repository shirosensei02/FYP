const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const core = require('drizzle-orm/sqlite-core');
  const orm = require('drizzle-orm');

  if (!core || typeof core.sqliteTable !== 'function' || typeof core.text !== 'function') {
    throw new Error('Required sqlite-core APIs are unavailable');
  }
  if (!orm || typeof orm.sql !== 'function') {
    throw new Error('Required sql tag API is unavailable');
  }

  const benignTable = core.sqliteTable('users', {
    name: core.text('name'),
  });

  const benignQuery = orm.sql`select ${benignTable.name} from ${benignTable}`;
  const benignSql = typeof benignQuery.toSQL === 'function'
    ? benignQuery.toSQL().sql
    : (typeof benignQuery.toQuery === 'function' ? benignQuery.toQuery().sql : String(benignQuery));

  if (typeof benignSql !== 'string' || !/select/i.test(benignSql) || !/from/i.test(benignSql)) {
    throw new Error('Benign query generation failed');
  }

  operation_completed = true;

  const payload = 'safe_name"; DROP TABLE audit_log;--';
  const maliciousTable = core.sqliteTable('products', {
    [payload]: core.text(payload),
  });

  const maliciousQuery = orm.sql`select ${maliciousTable[payload]} from ${maliciousTable}`;
  const maliciousSql = typeof maliciousQuery.toSQL === 'function'
    ? maliciousQuery.toSQL().sql
    : (typeof maliciousQuery.toQuery === 'function' ? maliciousQuery.toQuery().sql : String(maliciousQuery));

  const hasRawPayload = maliciousSql.includes(payload);
  const hasStatementBreak = /;\s*drop\s+table/i.test(maliciousSql);

  exploit_succeeded = !!(hasRawPayload || hasStatementBreak);
  evidence = `benign_sql=${JSON.stringify(benignSql)} malicious_sql=${JSON.stringify(maliciousSql)} hasRawPayload=${hasRawPayload} hasStatementBreak=${hasStatementBreak}`;
} catch (err) {
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = `setup_or_benign_error:${err && err.message ? err.message : String(err)}`;
  } else {
    exploit_succeeded = false;
    evidence = `malicious_blocked:${err && err.message ? err.message : String(err)}`;
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
