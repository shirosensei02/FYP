const path = require('node:path');
const fs = require('node:fs');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const _ = require('lodash');

  // Setup: ensure a unique marker path in /tmp and clean any test pollution state.
  const marker = path.join('/tmp', 'oracle_lodash_proto_pollution_' + process.pid + '_' + Date.now());
  fs.writeFileSync(marker, 'marker');

  // Reset potential prior pollution in this process context.
  try { delete Object.prototype.oraclePollutedFlag; } catch (_) {}

  // Benign operation: merge ordinary nested properties.
  const benignTarget = { a: 1 };
  const benignSource = { b: { c: 2 } };
  const benignResult = _.merge(benignTarget, benignSource);

  if (!benignResult || benignResult.b == null || benignResult.b.c !== 2 || benignResult.a !== 1) {
    throw new Error('Benign lodash.merge behavior did not succeed');
  }

  // Only now the relevant public operation is confirmed working.
  operation_completed = true;

  // Malicious input attempting prototype pollution.
  const target = {};
  const payload = JSON.parse('{"__proto__":{"oraclePollutedFlag":"YES"}}');

  try {
    _.merge(target, payload);
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'Malicious merge threw (blocked): ' + (e && e.message ? e.message : String(e));
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
    process.exit(0);
  }

  const polluted = ({}).oraclePollutedFlag === 'YES';
  exploit_succeeded = polluted;
  evidence = polluted
    ? 'Prototype polluted via _.merge using __proto__ payload'
    : 'No prototype pollution observed after malicious _.merge';

  // Cleanup marker and pollution if possible.
  try { fs.unlinkSync(marker); } catch (_) {}
  try { delete Object.prototype.oraclePollutedFlag; } catch (_) {}

} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Setup/module/benign failure: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));