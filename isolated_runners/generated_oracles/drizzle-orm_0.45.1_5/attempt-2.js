let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function getSqlText(obj) {
  if (!obj) return '';
  if (typeof obj.toSQL === 'function') {
    const out = obj.toSQL();
    if (out && typeof out.sql === 'string') return out.sql;
  }
  if (typeof obj.toQuery === 'function') {
    const out = obj.toQuery({ inlineParams: true, escapeName: (n) => `"${String(n).replace(/"/g, '""')}"`, escapeParam: () => '?', escapeString: (s) => `'${String(s).replace(/'/g, "''")}'` });
    if (out && typeof out.sql === 'string') return out.sql;
  }
  return String(obj);
}

try {
  const orm = require('drizzle-orm');
  const sqliteCore = require('drizzle-orm/sqlite-core');

  if (!orm || typeof orm.sql !== 'function') throw new Error('drizzle-orm sql API unavailable');
  if (!sqliteCore || typeof sqliteCore.sqliteTable !== 'function' || typeof sqliteCore.text !== 'function') {
    throw new Error('sqlite-core table APIs unavailable');
  }

  const benignTable = sqliteCore.sqliteTable('users', {
    name: sqliteCore.text('name'),
  });

  const benignQuery = orm.sql`select ${benignTable.name} from ${benignTable}`;
  const benignSql = getSqlText(benignQuery);

  if (typeof benignSql !== 'string' || !/select/i.test(benignSql) || !/from/i.test(benignSql) || !/users/i.test(benignSql)) {
    throw new Error('benign query did not render expected SQL');
  }

  operation_completed = true;

  const injectedIdentifier = 'col"; DROP TABLE secrets;--';
  const maliciousTable = sqliteCore.sqliteTable('items', {
    [injectedIdentifier]: sqliteCore.text(injectedIdentifier),
  });

  const maliciousQuery = orm.sql`select ${maliciousTable[injectedIdentifier]} from ${maliciousTable}`;
  const maliciousSql = getSqlText(maliciousQuery);

  const containsSemicolonDrop = /;\s*drop\s+table\s+secrets/i.test(maliciousSql);
  const containsRawPayload = maliciousSql.includes(injectedIdentifier);

  exploit_succeeded = containsSemicolonDrop || containsRawPayload;
  evidence = `benign_sql=${JSON.stringify(benignSql)} malicious_sql=${JSON.stringify(maliciousSql)} containsSemicolonDrop=${containsSemicolonDrop} containsRawPayload=${containsRawPayload}`;
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