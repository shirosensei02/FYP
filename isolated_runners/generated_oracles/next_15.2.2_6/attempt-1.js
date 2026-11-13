const fs = require('node:fs');
const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const result = { operation_completed, exploit_succeeded, evidence };
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const marker = path.join('/tmp', 'oracle-ghsa-f82v-jwr5-mffw-' + process.pid + '-' + Date.now() + '.txt');

  const utilsPath = require.resolve('next/dist/server/lib/server-ipc/utils');
  const utils = require(utilsPath);

  if (!utils || typeof utils.filterInternalHeaders !== 'function') {
    throw new Error('Publicly shipped utility function unavailable');
  }

  // Benign call: ordinary user header should survive filtering.
  const benignHeaders = {
    'x-user-header': 'ok',
    'accept': 'text/html'
  };
  utils.filterInternalHeaders(benignHeaders);

  if (benignHeaders['x-user-header'] !== 'ok') {
    throw new Error('Benign operation failed: ordinary header unexpectedly altered');
  }

  operation_completed = true;

  // Malicious input: forged middleware skip header without matching per-session id.
  const forgedHeaders = {
    'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware',
    'x-user-header': 'still-here'
  };

  let threwOnMalicious = false;
  try {
    utils.filterInternalHeaders(forgedHeaders);
  } catch (e) {
    threwOnMalicious = true;
    evidence = 'malicious call threw: ' + (e && e.message ? e.message : String(e));
  }

  if (threwOnMalicious) {
    exploit_succeeded = false;
  } else {
    const headerStillPresent = Object.prototype.hasOwnProperty.call(forgedHeaders, 'x-middleware-subrequest');
    exploit_succeeded = headerStillPresent;
    evidence = JSON.stringify({
      utilsPath,
      headerStillPresent,
      remainingKeys: Object.keys(forgedHeaders).sort()
    });
  }

  try {
    fs.writeFileSync(marker, evidence);
  } catch (_) {}
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
}

finish();