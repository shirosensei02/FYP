const { sql } = require('drizzle-orm');

function emit(operation_completed, exploit_succeeded, evidence) {
  const out = { operation_completed, exploit_succeeded, evidence: String(evidence) };
  console.log('ORACLE_RESULT ' + JSON.stringify(out));
}

try {
  if (!sql || typeof sql.identifier !== 'function') {
    emit(false, false, 'drizzle sql.identifier API unavailable');
  } else {
    const cfg = {
      escapeName: (name) => `"${String(name).replace(/"/g, '""')}"`,
      escapeParam: () => '?',
      escapeString: (s) => `'${String(s).replace(/'/g, "''")}'`,
      casing: undefined,
    };

    let benignQuery;
    try {
      const benign = sql`select ${sql.identifier(['users', 'email'])}`;
      benignQuery = benign.toQuery(cfg);
      if (!benignQuery || typeof benignQuery.sql !== 'string' || !benignQuery.sql.includes('"users"."email"')) {
        emit(false, false, 'benign operation did not produce expected identifier SQL');
        return;
      }
    } catch (e) {
      emit(false, false, 'benign operation failed: ' + (e && e.message ? e.message : e));
      return;
    }

    const operation_completed = true;

    try {
      const payload = 'email"; DROP TABLE audit_log; --';
      const malicious = sql`select ${sql.identifier(['users', payload])}`;
      const maliciousQuery = malicious.toQuery(cfg);
      const rendered = maliciousQuery && typeof maliciousQuery.sql === 'string' ? maliciousQuery.sql : '';

      const hasDrop = rendered.includes('DROP TABLE audit_log');
      const hasInjectedBreakout = rendered.includes('"; DROP TABLE');
      const exploit_succeeded = hasDrop && hasInjectedBreakout;

      emit(operation_completed, exploit_succeeded, 'benign=' + benignQuery.sql + ' | malicious=' + rendered);
    } catch (e) {
      emit(operation_completed, false, 'malicious input blocked with exception: ' + (e && e.message ? e.message : e));
    }
  }
} catch (e) {
  emit(false, false, 'unexpected failure: ' + (e && e.message ? e.message : e));
}
