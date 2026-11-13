'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function main() {
  const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

  try {
    const marker = 'drizzle_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
    const tmpDir = os.tmpdir();

    let core;
    try {
      core = require('drizzle-orm');
    } catch (e) {
      console.log('SETUP_ERROR core-module: ' + (e && e.message ? e.message : String(e)));
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    let pgCore;
    try {
      pgCore = require('drizzle-orm/pg-core');
    } catch (e) {
      console.log('SETUP_ERROR pg-core-module: ' + (e && e.message ? e.message : String(e)));
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    const { sql } = core;
    const { pgTable, text, integer, PgDialect } = pgCore;

    let dialect;
    try {
      dialect = new PgDialect();
    } catch (e) {
      console.log('SETUP_ERROR dialect-init: ' + (e && e.message ? e.message : String(e)));
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    // Define a simple table to exercise the benign public API: building a
    // SELECT query via the query builder / sql tag and compiling it to SQL
    // text + params using the dialect's sqlToQuery, which is the code path
    // responsible for escaping SQL identifiers (e.g. sql.identifier(), table
    // names interpolated via sql.raw/identifier helpers).
    let usersTable;
    try {
      usersTable = pgTable('users', {
        id: integer('id').primaryKey(),
        name: text('name'),
        secret: text('secret')
      });
    } catch (e) {
      console.log('SETUP_ERROR table-def: ' + (e && e.message ? e.message : String(e)));
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    // Benign operation: build a query referencing a normal, safe identifier
    // through sql.identifier() and compile it. This proves the relevant
    // public operation (identifier escaping + query compilation) works.
    let benignOk = false;
    try {
      const benignIdent = 'name';
      const benignQuery = sql`SELECT ${sql.identifier(benignIdent)} FROM ${usersTable} WHERE ${usersTable.id} = 1`;
      const built = dialect.sqlToQuery(benignQuery);
      if (built && typeof built.sql === 'string' && built.sql.length > 0) {
        // A safe identifier should be quoted with double quotes and contain
        // no stray injected SQL keywords beyond what we asked for.
        if (built.sql.includes('"name"') || built.sql.includes('name')) {
          benignOk = true;
        }
      }
    } catch (e) {
      console.log('BENIGN_OPERATION_ERROR: ' + (e && e.message ? e.message : String(e)));
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    if (!benignOk) {
      console.log('BENIGN_OPERATION_FAILED: unexpected result shape');
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    // Only now may operation_completed become true, since setup and benign
    // operation succeeded.
    result.operation_completed = true;

    // Malicious input: an identifier crafted to break out of the quoting
    // performed by sql.identifier(). In vulnerable versions (<=0.45.1),
    // double quotes inside the identifier are not escaped by doubling them,
    // so an attacker-controlled identifier string containing a double quote
    // can terminate the quoted identifier early and inject arbitrary SQL
    // into the compiled query text. We verify exploitation by inspecting the
    // compiled SQL string produced by the dialect: if the injected payload's
    // raw SQL keywords/fragments appear unescaped/unquoted in the output
    // (i.e., the embedded double-quote was not doubled to ""), the identifier
    // escaping is broken and injection succeeded. If the implementation
    // properly escapes the embedded quote (doubling it) or throws, the
    // injection is blocked.
    const injectedFragment = 'DROP TABLE users; --';
    const maliciousIdent = 'name" ; ' + injectedFragment + ' "';

    let exploitSucceeded = false;
    let evidence = '';
    try {
      const maliciousQuery = sql`SELECT ${sql.identifier(maliciousIdent)} FROM ${usersTable} WHERE ${usersTable.id} = 1`;
      const built = dialect.sqlToQuery(maliciousQuery);
      const compiled = (built && typeof built.sql === 'string') ? built.sql : '';

      // Proper escaping: a literal double quote inside an identifier must be
      // doubled ("") per SQL standard quoting rules. If the compiled SQL
      // contains a single, unescaped double-quote immediately followed by
      // non-quote content that matches our injected fragment verbatim
      // (i.e., the quote was not doubled), the identifier was not safely
      // escaped and the injected SQL fragment appears intact/unescaped in
      // the output, demonstrating the injection.
      const unsafePattern = '"' + maliciousIdent.replace(/"/g, '"') ;
      const rawInjectionPresent = compiled.includes(injectedFragment) && !compiled.includes('""');

      if (rawInjectionPresent) {
        exploitSucceeded = true;
        evidence = 'Malicious identifier was embedded into compiled SQL without doubling internal quotes, exposing injected fragment: ' + injectedFragment;
      } else if (compiled.includes('""')) {
        exploitSucceeded = false;
        evidence = 'Malicious identifier was safely escaped (internal quote doubled); compiled SQL: ' + compiled.slice(0, 200);
      } else {
        exploitSucceeded = false;
        evidence = 'Malicious identifier did not produce the injected fragment in compiled SQL; compiled SQL: ' + compiled.slice(0, 200);
      }
    } catch (e) {
      // A patched version may throw instead of silently producing broken SQL,
      // which counts as blocked (since setup and benign operation already
      // succeeded at this point).
      exploitSucceeded = false;
      evidence = 'Malicious identifier was rejected/blocked (exception): ' + (e && e.message ? e.message : String(e));
    }

    result.exploit_succeeded = exploitSucceeded;
    result.evidence = evidence;

    console.log('ORACLE_RESULT ' + JSON.stringify(result));
  } catch (e) {
    const failResult = {
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Unexpected top-level exception: ' + (e && e.message ? e.message : String(e))
    };
    console.log('ORACLE_RESULT ' + JSON.stringify(failResult));
  }
}

main();
