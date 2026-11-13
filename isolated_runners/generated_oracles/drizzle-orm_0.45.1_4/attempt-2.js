let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const drizzle = require('drizzle-orm');
  const sqliteCore = require('drizzle-orm/sqlite-core');

  const sql = drizzle && drizzle.sql;
  const sqliteTable = sqliteCore && sqliteCore.sqliteTable;
  const text = sqliteCore && sqliteCore.text;

  if (typeof sql !== 'function' || typeof sqliteTable !== 'function' || typeof text !== 'function') {
    throw new Error('required APIs unavailable');
  }

  const users = sqliteTable('users', {
    id: text('id'),
    name: text('name'),
  });

  const benign = sql`select ${users.id} from ${users}`;
  if (!benign || typeof benign.toQuery !== 'function') {
    throw new Error('benign query builder unavailable');
  }

  const benignBuilt = benign.toQuery({
    escapeName: (name) => `"${String(name).replace(/"/g, '""')}"`,
    escapeParam: (i) => '?',
    escapeString: (s) => `'${String(s).replace(/'/g, "''")}'`,
    casing: undefined,
  });

  const benignSql = String(benignBuilt && benignBuilt.sql || '');
  if (!benignSql.includes('"users"') || !benignSql.includes('"users"."id"')) {
    throw new Error('benign query did not compile as expected');
  }

  operation_completed = true;

  const marker = 'DRIZZLE_IDENT_INJECT_MARK';
  const payloadName = `evil"; select '${marker}' as p; --`;
  const evil = sqliteTable(payloadName, { c: text('c') });
  const maliciousQuery = sql`select ${evil.c} from ${evil}`;

  const malBuilt = maliciousQuery.toQuery({
    escapeName: (name) => `"${String(name).replace(/"/g, '""')}"`,
    escapeParam: (i) => '?',
    escapeString: (s) => `'${String(s).replace(/'/g, "''")}'`,
    casing: undefined,
  });

  const malSql = String(malBuilt && malBuilt.sql || '');
  const leaked = malSql.includes(marker) || /;\s*select\s+/i.test(malSql) || /--/.test(malSql);

  exploit_succeeded = leaked;
  evidence = JSON.stringify({ benignSql, malSql, leaked });
} catch (err) {
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error:' + (err && err.message ? err.message : String(err));
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_blocked:' + (err && err.message ? err.message : String(err));
  }
}

out();