let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const orm = require('drizzle-orm');
  const sqliteCore = require('drizzle-orm/sqlite-core');

  if (!orm || typeof orm.sql !== 'function') throw new Error('missing drizzle sql tag');
  if (!sqliteCore || typeof sqliteCore.sqliteTable !== 'function' || typeof sqliteCore.text !== 'function') {
    throw new Error('missing sqlite-core table/text APIs');
  }

  const users = sqliteCore.sqliteTable('users', { name: sqliteCore.text('name') });
  const benign = orm.sql`select ${users.name} from ${users}`;
  const benignChunks = benign && benign.queryChunks;
  if (!Array.isArray(benignChunks)) throw new Error('benign query chunks unavailable');

  const benignText = benignChunks.map((c) => {
    if (typeof c === 'string') return c;
    if (c && typeof c.value === 'string') return c.value;
    if (c && typeof c.sql === 'string') return c.sql;
    return Object.prototype.toString.call(c);
  }).join(' ');

  if (!/select/i.test(benignText)) throw new Error('benign operation did not build select SQL');

  operation_completed = true;

  const payload = 'x";DROP TABLE secrets;--';
  let mal;
  try {
    mal = orm.sql.identifier(payload);
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_exception:' + (e && e.message ? e.message : String(e));
    emit();
    return;
  }

  const malChunks = mal && mal.queryChunks;
  let chunkDump = '';
  if (Array.isArray(malChunks) && malChunks.length > 0) {
    const first = malChunks[0];
    if (first && Array.isArray(first.value)) {
      chunkDump = first.value.map((v) => String(v)).join(',');
    } else {
      chunkDump = String(first && first.value !== undefined ? first.value : first);
    }
  }

  const containsRawPayload = chunkDump.includes(payload);
  exploit_succeeded = containsRawPayload;
  evidence = 'benign_chunks=' + benignChunks.length + ' mal_chunk_dump=' + JSON.stringify(chunkDump) + ' contains_raw_payload=' + containsRawPayload;
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (e && e.message ? e.message : String(e));
}

emit();