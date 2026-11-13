'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = 'drizzle_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), marker + '_'));

    let drizzle;
    try {
      drizzle = require('drizzle-orm');
    } catch (e) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
      return;
    }

    // Locate the sql tag / identifier helper. drizzle-orm exports `sql` from main entry.
    const sql = drizzle.sql;
    if (!sql || typeof sql.identifier !== 'function') {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'sql.identifier helper not found on package export; cannot exercise target API' });
      return;
    }

    // --- Benign operation first ---
    let benignQueryText = '';
    try {
      const benignName = 'users';
      const benignFragment = sql`SELECT * FROM ${sql.identifier(benignName)}`;
      // Render to actual SQL text using toQuery (pg dialect style) if available,
      // else fall back to inspecting queryChunks/getSQL.
      if (typeof benignFragment.toQuery === 'function') {
        const q = benignFragment.toQuery({ escapeParam: (i) => '$' + (i + 1) });
        benignQueryText = q.sql;
      } else if (benignFragment.queryChunks) {
        // Fallback: manually stringify chunks looking for the identifier object render
        benignQueryText = JSON.stringify(benignFragment.queryChunks);
      } else {
        throw new Error('No renderable interface found on sql fragment');
      }

      const okBenign = typeof benignQueryText === 'string' &&
        benignQueryText.length > 0 &&
        benignQueryText.includes('"users"');

      if (!okBenign) {
        finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign identifier rendering did not produce expected quoted identifier: ' + benignQueryText });
        return;
      }
    } catch (e) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign operation threw: ' + String(e && e.message) });
      return;
    }

    operation_completed = true;

    // --- Malicious operation ---
    try {
      const maliciousName = 'users" WHERE 1=1; --';
      const maliciousFragment = sql`SELECT * FROM ${sql.identifier(maliciousName)}`;

      let maliciousQueryText = '';
      if (typeof maliciousFragment.toQuery === 'function') {
        const q = maliciousFragment.toQuery({ escapeParam: (i) => '$' + (i + 1) });
        maliciousQueryText = q.sql;
      } else if (maliciousFragment.queryChunks) {
        maliciousQueryText = JSON.stringify(maliciousFragment.queryChunks);
      } else {
        throw new Error('No renderable interface found on malicious sql fragment');
      }

      // Proper escaping would double internal quotes: `"` -> `""`.
      // Expected safe form: "users"" WHERE 1=1; --"  (quote doubled, still one token)
      const safeForm = '"' + maliciousName.replace(/"/g, '""') + '"';
      const containsSafeForm = maliciousQueryText.includes(safeForm);

      // Vulnerable form: naive wrap without doubling quotes, e.g. "users" WHERE 1=1; --"
      // which breaks out of the identifier (the quote closes early, leaving
      // ` WHERE 1=1; --"` as raw unescaped SQL text outside of any identifier quoting).
      const naiveForm = '"' + maliciousName + '"';
      const containsNaiveBreakout = maliciousQueryText.includes(naiveForm) && !containsSafeForm;

      if (containsSafeForm) {
        exploit_succeeded = false;
        evidence = 'Identifier quotes were properly escaped/doubled; injected payload remained confined inside a single identifier token: ' + maliciousQueryText;
      } else if (containsNaiveBreakout) {
        exploit_succeeded = true;
        evidence = 'Identifier quoting was broken: malicious identifier text escaped its quoted boundary producing injectable raw SQL: ' + maliciousQueryText;
      } else {
        // Ambiguous rendering: check more loosely for an un-doubled quote adjacent to injected SQL keywords
        const hasBareBreakoutPattern = /"\s*WHERE\s+1=1/i.test(maliciousQueryText);
        if (hasBareBreakoutPattern) {
          exploit_succeeded = true;
          evidence = 'Detected unescaped quote allowing SQL keywords to escape identifier context: ' + maliciousQueryText;
        } else {
          exploit_succeeded = false;
          evidence = 'No clear breakout pattern detected; treating as safely escaped: ' + maliciousQueryText;
        }
      }
    } catch (e) {
      // An exception here, after benign success, counts as blocked.
      exploit_succeeded = false;
      evidence = 'Malicious call raised an exception after benign success (treated as blocked): ' + String(e && e.message);
    }

    // cleanup tmp dir (best-effort)
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}

    finish({ operation_completed, exploit_succeeded, evidence });
  } catch (outerErr) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected top-level error: ' + String(outerErr && outerErr.message) });
  }
})();
