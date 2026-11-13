'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

(async () => {
  try {
    const marker = 'drizzle_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
    let tmpDir;
    try {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), marker + '_'));
    } catch (e) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'tmp setup failed: ' + String(e && e.message) });
      return;
    }

    let sqliteCore;
    try {
      sqliteCore = require('drizzle-orm/sqlite-core');
    } catch (e) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed (sqlite-core): ' + String(e && e.message) });
      return;
    }

    const { sqliteTable, text, SQLiteSyncDialect } = sqliteCore;
    if (typeof sqliteTable !== 'function' || typeof text !== 'function' || typeof SQLiteSyncDialect !== 'function') {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'required exports (sqliteTable/text/SQLiteSyncDialect) not found on drizzle-orm/sqlite-core' });
      return;
    }

    let dialect;
    try {
      dialect = new SQLiteSyncDialect();
    } catch (e) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'failed to construct SQLiteSyncDialect: ' + String(e && e.message) });
      return;
    }

    // --- Benign operation first ---
    let benignSqlText = '';
    try {
      const benignTable = sqliteTable('users_benign', {
        id: text('id'),
        name: text('name')
      });

      const benignSelect = dialect.sqlToQuery(
        require('drizzle-orm').sql`SELECT * FROM ${benignTable}`
      );

      if (!benignSelect || typeof benignSelect.sql !== 'string') {
        finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign sqlToQuery did not return a string sql field' });
        return;
      }
      benignSqlText = benignSelect.sql;

      const okBenign = benignSqlText.includes('"users_benign"');
      if (!okBenign) {
        finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign rendering did not produce expected quoted table identifier: ' + benignSqlText });
        return;
      }
    } catch (e) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign operation threw: ' + String(e && e.message) });
      return;
    }

    const operation_completed = true;
    let exploit_succeeded = false;
    let evidence = '';

    // --- Malicious operation ---
    try {
      const maliciousTableName = 'users" WHERE 1=1; --';

      const maliciousTable = sqliteTable(maliciousTableName, {
        id: text('id'),
        name: text('name')
      });

      const { sql } = require('drizzle-orm');
      const maliciousSelect = dialect.sqlToQuery(sql`SELECT * FROM ${maliciousTable}`);

      if (!maliciousSelect || typeof maliciousSelect.sql !== 'string') {
        finish({ operation_completed: false, exploit_succeeded: false, evidence: 'malicious sqlToQuery did not return a string sql field (treated as blocked/non-exploitable)' });
        return;
      }

      const maliciousSqlText = maliciousSelect.sql;

      const safeForm = '"' + maliciousTableName.replace(/"/g, '""') + '"';
      const containsSafeForm = maliciousSqlText.includes(safeForm);

      const naiveForm = '"' + maliciousTableName + '"';
      const containsNaiveBreakout = maliciousSqlText.includes(naiveForm) && !containsSafeForm;
      const hasBareBreakoutPattern = /"\s*WHERE\s+1=1/i.test(maliciousSqlText) && !containsSafeForm;

      if (containsSafeForm) {
        exploit_succeeded = false;
        evidence = 'Identifier quotes were properly escaped/doubled; injected payload remained confined inside a single identifier token: ' + maliciousSqlText;
      } else if (containsNaiveBreakout || hasBareBreakoutPattern) {
        exploit_succeeded = true;
        evidence = 'Identifier quoting was broken: malicious table name escaped its quoted boundary producing injectable raw SQL: ' + maliciousSqlText;
      } else {
        exploit_succeeded = false;
        evidence = 'No clear breakout pattern detected; treating as safely escaped: ' + maliciousSqlText;
      }

      finish({ operation_completed, exploit_succeeded, evidence });
    } catch (e) {
      finish({
        operation_completed,
        exploit_succeeded: false,
        evidence: 'Malicious call raised an exception after benign success (treated as blocked): ' + String(e && e.message)
      });
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
    }
  } catch (outerErr) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected top-level error: ' + String(outerErr && outerErr.message) });
  }
})();
