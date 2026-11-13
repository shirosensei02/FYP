'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

function renderFragment(frag) {
  // Try several known rendering strategies across drizzle-orm versions.
  if (frag && typeof frag.toQuery === 'function') {
    const q = frag.toQuery({ escapeParam: (i) => '$' + (i + 1) });
    if (q && typeof q.sql === 'string') return q.sql;
  }
  if (frag && typeof frag.getSQL === 'function') {
    const inner = frag.getSQL();
    return renderFragment(inner);
  }
  if (frag && Array.isArray(frag.queryChunks)) {
    return JSON.stringify(frag.queryChunks);
  }
  throw new Error('No renderable interface found on sql fragment');
}

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const marker = 'drizzle_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
    let tmpDir;
    try {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), marker + '_'));
    } catch (e) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'tmp setup failed: ' + String(e && e.message) });
      return;
    }

    let drizzle;
    try {
      drizzle = require('drizzle-orm');
    } catch (e) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
      return;
    }

    const sql = drizzle.sql;
    if (!sql || typeof sql !== 'function') {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'sql tagged-template helper not found on package export; cannot exercise target API' });
      return;
    }

    // Find an identifier-escaping helper. Different versions expose it differently.
    // Prefer sql.identifier if present; otherwise fall back to the internal name
    // used by table/column identifier rendering: sql.raw with manual quoting is NOT
    // what we want to test (that bypasses escaping entirely). We specifically need
    // the library's own identifier-quoting path, which historically is accessible
    // via `sql.identifier` or via a Name/SQLIdentifier wrapper from 'drizzle-orm/sql'.
    let identifierFn = null;
    if (typeof sql.identifier === 'function') {
      identifierFn = sql.identifier;
    } else {
      try {
        const sqlModule = require('drizzle-orm/sql');
        if (sqlModule && typeof sqlModule.sql === 'function' && typeof sqlModule.sql.identifier === 'function') {
          identifierFn = sqlModule.sql.identifier;
        } else if (sqlModule && typeof sqlModule.name === 'function') {
          identifierFn = sqlModule.name;
        }
      } catch (_) { /* ignore */ }
    }

    if (!identifierFn) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'identifier escaping helper not found on package export; cannot exercise target API' });
      return;
    }

    // --- Benign operation first ---
    let benignQueryText = '';
    try {
      const benignName = 'users';
      const benignFragment = sql`SELECT * FROM ${identifierFn(benignName)}`;
      benignQueryText = renderFragment(benignFragment);

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
      const maliciousFragment = sql`SELECT * FROM ${identifierFn(maliciousName)}`;
      const maliciousQueryText = renderFragment(maliciousFragment);

      // Proper escaping doubles internal quotes: `"` -> `""`.
      // Expected safe form: "users"" WHERE 1=1; --"  (quote doubled, single token)
      const safeForm = '"' + maliciousName.replace(/"/g, '""') + '"';
      const containsSafeForm = maliciousQueryText.includes(safeForm);

      // Vulnerable (naive) form: wraps without doubling, e.g. "users" WHERE 1=1; --"
      // The quote closes early, leaving ` WHERE 1=1; --"` as raw SQL outside quoting.
      const naiveForm = '"' + maliciousName + '"';
      const containsNaiveBreakout = maliciousQueryText.includes(naiveForm) && !containsSafeForm;
      const hasBareBreakoutPattern = /"\s*WHERE\s+1=1/i.test(maliciousQueryText);

      if (containsSafeForm) {
        exploit_succeeded = false;
        evidence = 'Identifier quotes were properly escaped/doubled; injected payload remained confined inside a single identifier token: ' + maliciousQueryText;
      } else if (containsNaiveBreakout || hasBareBreakoutPattern) {
        exploit_succeeded = true;
        evidence = 'Identifier quoting was broken: malicious identifier text escaped its quoted boundary producing injectable raw SQL: ' + maliciousQueryText;
      } else {
        exploit_succeeded = false;
        evidence = 'No clear breakout pattern detected; treating as safely escaped: ' + maliciousQueryText;
      }
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'Malicious call raised an exception after benign success (treated as blocked): ' + String(e && e.message);
    }

    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}

    finish({ operation_completed, exploit_succeeded, evidence });
  } catch (outerErr) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected top-level error: ' + String(outerErr && outerErr.message) });
  }
})();
