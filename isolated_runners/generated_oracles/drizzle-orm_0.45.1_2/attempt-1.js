'use strict';
const path = require('node:path');

function main() {
  let sql;
  try {
    const mod = require('drizzle-orm');
    sql = mod.sql;
    if (!sql || typeof sql.identifier !== 'function') {
      throw new Error('sql.identifier not available on drizzle-orm module');
    }
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup failed: could not load drizzle-orm sql.identifier: ' + String(e && e.message || e)
    }));
    return;
  }

  const { SQLiteSyncDialect } = require('drizzle-orm/sqlite-core');

  let dialect;
  try {
    dialect = new SQLiteSyncDialect();
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup failed: could not construct SQLiteSyncDialect: ' + String(e && e.message || e)
    }));
    return;
  }

  // Marker for uniqueness/traceability (no filesystem writes needed for this check)
  const marker = 'drizzle_sqli_check_' + process.pid + '_' + Date.now();

  // Step 1: benign input - ensure normal identifier works end-to-end.
  let benignSqlText;
  try {
    const benignIdentifier = 'normal_column_name_' + marker;
    const benignChunk = sql.identifier(benignIdentifier);
    const built = dialect.sqlToQuery(benignChunk);
    benignSqlText = built.sql;

    if (typeof benignSqlText !== 'string' || !benignSqlText.includes(benignIdentifier)) {
      throw new Error('benign identifier was not rendered as expected: ' + JSON.stringify(benignSqlText));
    }
    // Expect it to be wrapped in double quotes for sqlite dialect, with no stray characters.
    const expectedBenign = '"' + benignIdentifier + '"';
    if (benignSqlText.trim() !== expectedBenign) {
      throw new Error('benign identifier did not match expected quoting: ' + JSON.stringify(benignSqlText));
    }
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign operation failed: ' + String(e && e.message || e)
    }));
    return;
  }

  // Benign operation succeeded; we may now proceed to malicious input.
  let operation_completed = true;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Malicious input: attacker-controlled identifier containing an embedded
    // double-quote delimiter, attempting to break out of the quoted identifier
    // and inject additional SQL syntax (classic dynamic-sort/alias injection).
    const maliciousIdentifier = 'id" , (SELECT 1) AS "x';
    const maliciousChunk = sql.identifier(maliciousIdentifier);
    const builtMalicious = dialect.sqlToQuery(maliciousChunk);
    const renderedSql = builtMalicious.sql;

    if (typeof renderedSql !== 'string') {
      throw new Error('malicious identifier rendering produced non-string output');
    }

    // If the identifier was properly escaped, every embedded double-quote
    // character in the original identifier must have been doubled ("" ) when
    // placed inside the quoted identifier, so the rendered SQL text should NOT
    // contain an unescaped sequence that terminates the identifier early
    // (i.e. a single " followed by something other than another ").
    //
    // We detect successful injection by checking whether the rendered SQL
    // contains the malicious payload's closing quote immediately followed by
    // a space/comma (i.e. the identifier delimiter was terminated early,
    // allowing extra SQL tokens to appear outside of the quoted identifier).
    //
    // A safe (patched) implementation would render something like:
    //   "id"" , (SELECT 1) AS ""x"
    // where every embedded quote is doubled, keeping the whole malicious
    // string as a single opaque identifier (no syntactic breakout).
    //
    // A vulnerable (unpatched) implementation renders:
    //   "id" , (SELECT 1) AS "x"
    // where the first " terminates the identifier, exposing the injected
    // SQL tokens `, (SELECT 1) AS` outside of any quotes.

    const vulnerablePattern = '"id" , (SELECT 1) AS "x"';
    const safePattern = '"id"" , (SELECT 1) AS ""x"';

    const normalizedRendered = renderedSql.trim();

    if (normalizedRendered === vulnerablePattern) {
      exploit_succeeded = true;
      evidence = 'Malicious identifier broke out of quoting; rendered SQL: ' + JSON.stringify(normalizedRendered);
    } else if (normalizedRendered === safePattern) {
      exploit_succeeded = false;
      evidence = 'Malicious identifier was safely escaped; rendered SQL: ' + JSON.stringify(normalizedRendered);
    } else {
      // Fallback heuristic: check for unescaped quote breakout by counting
      // double-quote characters. If the identifier's embedded quote was
      // doubled correctly, the count of "" pairs would differ from a
      // simple single-quote breakout. We check whether the substring
      // ', (SELECT 1) AS "x"' appears outside of doubled quotes, i.e.
      // whether a bare (non-doubled) quote immediately precedes ' , (SELECT 1)'.
      const breakoutMarker = '" , (SELECT 1) AS "x"';
      const escapedMarker = '"" , (SELECT 1) AS ""x"';
      if (normalizedRendered.includes(breakoutMarker) && !normalizedRendered.includes(escapedMarker)) {
        exploit_succeeded = true;
        evidence = 'Malicious identifier broke out of quoting (heuristic match); rendered SQL: ' + JSON.stringify(normalizedRendered);
      } else if (normalizedRendered.includes(escapedMarker)) {
        exploit_succeeded = false;
        evidence = 'Malicious identifier was safely escaped (heuristic match); rendered SQL: ' + JSON.stringify(normalizedRendered);
      } else {
        // Could not determine clearly; treat as blocked only if no raw
        // injection markers are present outside quotes.
        exploit_succeeded = false;
        evidence = 'Could not confirm injection pattern; rendered SQL: ' + JSON.stringify(normalizedRendered);
      }
    }
  } catch (e) {
    // An exception from the malicious call counts as blocked, since setup
    // and benign operation already succeeded.
    exploit_succeeded = false;
    evidence = 'malicious call raised exception (treated as blocked): ' + String(e && e.message || e);
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed,
    exploit_succeeded,
    evidence
  }));
}

main();
