const { sql } = require('drizzle-orm');

function emit(operation_completed, exploit_succeeded, evidence) {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence),
  }));
}

try {
  if (!sql || typeof sql.identifier !== 'function') {
    emit(false, false, 'sql.identifier API unavailable');
  } else {
    const cfg = {
      escapeName: (name) => `"${String(name).replace(/"/g, '""')}"`,
      escapeParam: () => '?',
      escapeString: (s) => `'${String(s).replace(/'/g, "''")}'`,
      casing: undefined,
    };

    let benignRendered = '';
    try {
      const benignQuery = sql`select ${sql.identifier('safe_column')}`.toQuery(cfg);
      benignRendered = benignQuery && typeof benignQuery.sql === 'string' ? benignQuery.sql : '';
      if (!benignRendered || !benignRendered.includes('"safe_column"')) {
        emit(false, false, 'benign operation did not render expected identifier SQL: ' + benignRendered);
        return;
      }
    } catch (e) {
      emit(false, false, 'benign operation failed: ' + (e && e.message ? e.message : e));
      return;
    }

    const operation_completed = true;

    try {
      const payload = 'safe_column"; DROP TABLE audit_log; --';
      const maliciousQuery = sql`select ${sql.identifier(payload)}`.toQuery(cfg);
      const maliciousRendered = maliciousQuery && typeof maliciousQuery.sql === 'string' ? maliciousQuery.sql : '';

      const lower = maliciousRendered.toLowerCase();
      const hasSelectPrefix = lower.startsWith('select ');

      const hasUnquotedDrop = /(^|[^a-z0-9_])drop\s+table\s+audit_log([^a-z0-9_]|$)/i.test(maliciousRendered);
      const hasUnquotedComment = /(^|\s)--/.test(maliciousRendered);
      const exploit_succeeded = hasSelectPrefix && hasUnquotedDrop && hasUnquotedComment;

      emit(operation_completed, exploit_succeeded, 'benign=' + benignRendered + ' | malicious=' + maliciousRendered);
    } catch (e) {
      emit(operation_completed, false, 'malicious input blocked with exception: ' + (e && e.message ? e.message : e));
    }
  }
} catch (e) {
  emit(false, false, 'unexpected failure: ' + (e && e.message ? e.message : e));
}
