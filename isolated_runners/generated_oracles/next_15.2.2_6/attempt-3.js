const fs = require('node:fs');
const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const filterPath = require.resolve('next/dist/server/lib/server-ipc/utils');
  const filterMod = require(filterPath);
  if (!filterMod || typeof filterMod.filterInternalHeaders !== 'function') {
    throw new Error('filter api unavailable');
  }

  const filterInternalHeaders = filterMod.filterInternalHeaders;

  // Benign operation first: ordinary headers should pass through.
  const benign = { accept: 'text/html', 'x-user-header': 'ok' };
  filterInternalHeaders(benign);
  if (benign['x-user-header'] !== 'ok') {
    throw new Error('benign behavior mismatch');
  }

  operation_completed = true;

  // Malicious input: forged bypass header without trusted subrequest id.
  const forged = {
    'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware',
    'x-user-header': 'still-here'
  };

  try {
    filterInternalHeaders(forged);
  } catch (e) {
    exploit_succeeded = false;
    evidence = JSON.stringify({
      filterPath,
      blockedByException: true,
      message: e && e.message ? String(e.message) : String(e)
    });
    finish();
    return;
  }

  const hasBypassHeader = Object.prototype.hasOwnProperty.call(forged, 'x-middleware-subrequest');
  const hasSessionGuardCode = /x-middleware-subrequest-id/.test(String(filterInternalHeaders));

  // Vulnerable builds: guard code absent and bypass header survives.
  // Patched builds: guard code present (and typically strips forged header).
  exploit_succeeded = hasBypassHeader && !hasSessionGuardCode;

  const markerDir = path.join('/tmp', 'oracle-ghsa-f82v-jwr5-mffw-' + process.pid + '-' + Date.now());
  try {
    fs.mkdirSync(markerDir, { recursive: true });
    fs.writeFileSync(
      path.join(markerDir, 'evidence.json'),
      JSON.stringify({ hasBypassHeader, hasSessionGuardCode, keysAfterFilter: Object.keys(forged).sort() })
    );
  } catch (_) {}

  evidence = JSON.stringify({
    filterPath,
    hasBypassHeader,
    hasSessionGuardCode,
    keysAfterFilter: Object.keys(forged).sort(),
    markerDir
  });
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
}

finish();