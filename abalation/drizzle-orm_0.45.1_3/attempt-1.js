'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function main() {
  const marker = 'drizzle_oracle_' + Math.random().toString(36).slice(2) + '_' + Date.now();
  const tmpMarkerFile = path.join(os.tmpdir(), marker + '.txt');

  let pgCore;
  try {
    fs.writeFileSync(tmpMarkerFile, 'marker-' + marker, 'utf8');
    pgCore = require('drizzle-orm/pg-core');
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup_failed: module resolution or tmp fixture error: ' + String(e && e.message || e)
    });
    return;
  }

  const { pgTable, text } = pgCore;

  if (typeof pgTable !== 'function' || typeof text !== 'function') {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'setup_failed: pgTable or text export missing from drizzle-orm/pg-core'
    });
    return;
  }

  // ---- Benign operation: build a normal table, generate SQL, confirm well-formed output ----
  let benignSqlText = null;
  try {
    const benignTable = pgTable('users_' + marker.replace(/[^a-zA-Z0-9_]/g, ''), {
      id: text('id'),
      name: text('name')
    });

    const { getTableConfig } = pgCore;
    const cfg = getTableConfig(benignTable);
    if (!cfg || !cfg.name || !Array.isArray(cfg.columns) || cfg.columns.length !== 2) {
      throw new Error('benign table config malformed');
    }

    // Use the SQL template helper to render an identifier-based fragment.
    const { sql } = require('drizzle-orm');
    const query = sql`SELECT * FROM ${benignTable}`;
    const builtQuery = query.toQuery ? query.toQuery() : null;

    // Fallback: use dialect-level identifier escaping directly if available via PgDialect
    let renderedSql = null;
    try {
      const { PgDialect } = pgCore;
      if (PgDialect) {
        const dialect = new PgDialect();
        const built = dialect.sqlToQuery(query);
        renderedSql = built.sql;
      }
    } catch (innerErr) {
      // ignore, fall back below
    }

    if (!renderedSql && builtQuery && typeof builtQuery.sql === 'string') {
      renderedSql = builtQuery.sql;
    }

    if (!renderedSql || typeof renderedSql !== 'string' || renderedSql.length === 0) {
      throw new Error('benign SQL rendering produced no output');
    }

    // Confirm the benign table name appears properly quoted in the SQL.
    if (!renderedSql.includes(cfg.name)) {
      throw new Error('benign SQL rendering did not include expected table name');
    }

    benignSqlText = renderedSql;
  } catch (e) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign_operation_failed: ' + String(e && e.message || e)
    });
    return;
  }

  // Benign operation succeeded; operation_completed may now become true.
  let operation_completed = true;

  // ---- Malicious operation: table name with embedded quote + SQL injection payload ----
  const payload = 'evil" ; DROP TABLE users; --';
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const { sql, PgDialect } = require('drizzle-orm');
    const maliciousTable = pgTable(payload, {
      id: text('id')
    });

    const query = sql`SELECT * FROM ${maliciousTable}`;

    let renderedSql = null;
    try {
      if (PgDialect) {
        const dialect = new PgDialect();
        const built = dialect.sqlToQuery(query);
        renderedSql = built.sql;
      }
    } catch (innerErr) {
      // If the dialect throws while building SQL for a malicious identifier,
      // that is a legitimate 'blocked' outcome, not a crash of our harness.
      renderedSql = null;
      evidence = 'dialect_threw_on_malicious_identifier: ' + String(innerErr && innerErr.message || innerErr);
    }

    if (renderedSql === null && evidence === '') {
      const built2 = query.toQuery ? query.toQuery() : null;
      if (built2 && typeof built2.sql === 'string') {
        renderedSql = built2.sql;
      }
    }

    if (renderedSql && typeof renderedSql === 'string') {
      // Vulnerable behavior: the raw payload (unescaped quote + SQL) appears verbatim,
      // i.e. the closing quote of the identifier is immediately followed by the
      // injected SQL fragment without the quote being doubled for escaping.
      const rawInjectionPattern = payload; // e.g. evil" ; DROP TABLE users; --
      const safeEscapedPattern = payload.replace(/"/g, '""'); // evil"" ; DROP TABLE users; --

      const containsRawUnescaped = renderedSql.includes(rawInjectionPattern);
      const containsSafelyEscaped = renderedSql.includes(safeEscapedPattern);

      if (containsRawUnescaped && !containsSafelyEscaped) {
        exploit_succeeded = true;
        evidence = 'malicious identifier rendered unescaped in generated SQL: ' + renderedSql;
      } else if (containsSafelyEscaped) {
        exploit_succeeded = false;
        evidence = 'malicious identifier was properly escaped (doubled quotes) in generated SQL: ' + renderedSql;
      } else {
        // Neither raw nor safely-escaped pattern found; treat as blocked (not injected)
        exploit_succeeded = false;
        evidence = 'malicious payload not found verbatim in generated SQL (likely escaped/altered): ' + renderedSql;
      }
    } else {
      // No SQL text could be produced at all (either dialect threw, or no builder available).
      exploit_succeeded = false;
      if (!evidence) {
        evidence = 'no SQL text could be rendered for malicious identifier; treated as blocked';
      }
    }
  } catch (e) {
    // Exception during malicious call, after benign success => blocked.
    exploit_succeeded = false;
    evidence = 'malicious_call_threw_after_benign_success: ' + String(e && e.message || e);
  }

  try {
    fs.unlinkSync(tmpMarkerFile);
  } catch (_) {
    // best-effort cleanup; ignore
  }

  finish({
    operation_completed: operation_completed,
    exploit_succeeded: exploit_succeeded,
    evidence: evidence + ' | benign_sql_sample=' + (benignSqlText ? benignSqlText.slice(0, 120) : 'null')
  });
}

try {
  main();
} catch (fatal) {
  // Any truly unexpected crash outside our controlled try/catch blocks.
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'fatal_uncaught_exception: ' + String(fatal && fatal.message || fatal)
  }));
}
