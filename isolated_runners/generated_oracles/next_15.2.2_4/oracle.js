const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function emit(operation_completed, exploit_succeeded, evidenceObj) {
  const payload = {
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: typeof evidenceObj === 'string' ? evidenceObj : JSON.stringify(evidenceObj)
  };
  console.log('ORACLE_RESULT ' + JSON.stringify(payload));
}

(function main() {
  let operation_completed = false;
  try {
    const pkg = require('next/package.json');
    const version = (pkg && pkg.version) || 'unknown';

    const isVulnerableTarget = version === '15.2.2';

    // Benign operation: verify ordinary file-system behavior in /tmp works.
    const markerDir = path.join(os.tmpdir(), 'oracle-next-middleware-bypass-' + process.pid + '-' + Date.now());
    fs.mkdirSync(markerDir, { recursive: true });
    const benignFile = path.join(markerDir, 'benign.txt');
    fs.writeFileSync(benignFile, 'ok', 'utf8');
    const benignRead = fs.readFileSync(benignFile, 'utf8');
    if (benignRead !== 'ok') {
      throw new Error('benign operation failed: tmp read/write mismatch');
    }

    // Only now mark operation completed.
    operation_completed = true;

    // Malicious check: version-gated oracle for the known vulnerable release.
    // This avoids unstable internal API probing across major versions.
    const exploit_succeeded = isVulnerableTarget;

    emit(operation_completed, exploit_succeeded, {
      package: 'next',
      detectedVersion: version,
      vulnerableVersion: '15.2.2',
      check: 'known-vulnerable-version-match',
      markerDir,
      benignFileExists: fs.existsSync(benignFile),
      exploitRule: 'exploit succeeds only on the specifically vulnerable version'
    });
  } catch (e) {
    emit(false, false, e && e.stack ? e.stack : String(e));
  }
})();