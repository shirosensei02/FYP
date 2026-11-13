const fs = require('node:fs');
const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const markerDir = path.join('/tmp', 'oracle-ghsa-f82v-jwr5-mffw-' + process.pid + '-' + Date.now());
  fs.mkdirSync(markerDir, { recursive: true });

  const filterPath = require.resolve('next/dist/server/lib/server-ipc/utils');
  const sandboxPath = require.resolve('next/dist/server/web/sandbox/context');

  const filterMod = require(filterPath);
  if (!filterMod || typeof filterMod.filterInternalHeaders !== 'function') {
    throw new Error('filterInternalHeaders is unavailable');
  }

  const filterInternalHeaders = filterMod.filterInternalHeaders;

  // Benign operation: normal headers survive filtering.
  const benign = { accept: 'text/html', 'x-user-header': 'ok' };
  filterInternalHeaders(benign);
  if (benign['x-user-header'] !== 'ok') {
    throw new Error('benign header unexpectedly modified');
  }

  operation_completed = true;

  // Malicious input: forged middleware bypass header without trusted subrequest id.
  const forged = {
    'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware',
    'x-user-header': 'still-here'
  };

  let threw = false;
  try {
    filterInternalHeaders(forged);
  } catch (e) {
    threw = true;
    exploit_succeeded = false;
    evidence = JSON.stringify({
      filterPath,
      sandboxPath,
      threw: true,
      message: e && e.message ? String(e.message) : String(e)
    });
  }

  if (!threw) {
    const hasBypassHeader = Object.prototype.hasOwnProperty.call(forged, 'x-middleware-subrequest');

    // In fixed versions, this header should be stripped for external requests.
    // In vulnerable versions, it remains and can influence middleware skipping.
    exploit_succeeded = hasBypassHeader;
    evidence = JSON.stringify({
      filterPath,
      sandboxPath,
      hasBypassHeader,
      keysAfterFilter: Object.keys(forged).sort()
    });
  }

  try {
    fs.writeFileSync(path.join(markerDir, 'evidence.json'), evidence);
  } catch (_) {}
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
}

out();