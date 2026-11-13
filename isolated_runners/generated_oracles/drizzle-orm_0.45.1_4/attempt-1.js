const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const result = { operation_completed, exploit_succeeded, evidence };
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const drizzle = require('drizzle-orm');
  const sqliteCore = require('drizzle-orm/sqlite-core');

  if (!drizzle || typeof drizzle.sql !== 'function') {
    throw new Error('drizzle-orm sql helper unavailable');
  }
  if (!sqliteCore || typeof sqliteCore.sqliteTable !== 'function' || typeof sqliteCore.text !== 'function') {
    throw new Error('sqlite-core builders unavailable');
  }

  const { sql } = drizzle;
  const { sqliteTable, text } = sqliteCore;

  const benignTable = sqliteTable('users', {
    id: text('id'),
    name: text('name'),
  });

  const benignQuery = sql`select ${benignTable.id} from ${benignTable}`;
  const benignSqlText = String(benignQuery && benignQuery.sql ? benignQuery.sql : '');

  if (!benignSqlText || benignSqlText.toLowerCase().indexOf('select') === -1) {
    throw new Error('benign query did not build expected SQL');
  }

  operation_completed = true;

  const marker = 'inj_marker_' + path.basename(__filename || 'oracle');
  const payloadName = `safe\" where 1=1; -- ${marker}`;
  const evilTable = sqliteTable(payloadName, {
    col: text('col'),
  });

  const evilQuery = sql`select ${evilTable.col} from ${evilTable}`;
  const evilSqlText = String(evilQuery && evilQuery.sql ? evilQuery.sql : '');

  const hasRawInjection = evilSqlText.includes('where 1=1; --') || evilSqlText.includes('; --') || evilSqlText.includes(marker);

  exploit_succeeded = hasRawInjection;
  evidence = JSON.stringify({ benignSqlText, evilSqlText, marker, hasRawInjection });
} catch (err) {
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error:' + (err && err.message ? err.message : String(err));
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_blocked:' + (err && err.message ? err.message : String(err));
  }
}

finish();