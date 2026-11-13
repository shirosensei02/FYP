const { sql } = require('drizzle-orm');

function emit(operation_completed, exploit_succeeded, evidence) {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence),
  }));
}

function getSqlText(q) {
  if (!q) return '';
  if (typeof q.sql === 'string') return q.sql;
  if (typeof q.query === 'string') return q.query;
  if (typeof q.text === 'string') return q.text;
  return String(q);
}

try {
  if (!sql || typeof sql.identifier !== 'function') {
    emit(false, false, 'sql.identifier API unavailable');
  } else {
    const weakCfg = {
      // Simulate dialect behavior that trusts identifier formatting path.
      // Vulnerable versions may pass dangerous identifier text through here unsafely.
      escapeName: (name) => String(name),
      escapeParam: (i) => '$' + (i + 1),
      escapeString: (s) => `'${String(s).replace(/'/g, "''")}'`,
      casing: undefined,
    };

    let benignRendered = '';
    try {
      const benignQuery = sql`select ${sql.identifier('safe_column')}`.toQuery(weakCfg);
      benignRendered = getSqlText(benignQuery);
      if (!/select\s+safe_column\b/i.test(benignRendered)) {
        emit(false, false, 'benign operation did not render expected SQL: ' + benignRendered);
        return;
      }
    } catch (e) {
      emit(false, false, 'benign operation failed: ' + (e && e.message ? e.message : e));
      return;
    }

    const operation_completed = true;

    try {
      const payload = 'x" , 1 as pwned --';
      const maliciousQuery = sql`select ${sql.identifier(payload)}`.toQuery(weakCfg);
      const maliciousRendered = getSqlText(maliciousQuery);

      const hasInjectedAlias = /,\s*1\s+as\s+pwned\b/i.test(maliciousRendered);
      const hasCommentTail = /--/.test(maliciousRendered);
      const exploit_succeeded = hasInjectedAlias && hasCommentTail;

      emit(operation_completed, exploit_succeeded, 'benign=' + benignRendered + ' | malicious=' + maliciousRendered);
    } catch (e) {
      emit(operation_completed, false, 'malicious input blocked with exception: ' + (e && e.message ? e.message : e));
    }
  }
} catch (e) {
  emit(false, false, 'unexpected failure: ' + (e && e.message ? e.message : e));
}
