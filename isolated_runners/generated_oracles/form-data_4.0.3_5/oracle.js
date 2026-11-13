const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const FormData = require('form-data');

  // Setup marker in /tmp only.
  const markerDir = path.join(os.tmpdir(), 'oracle-form-data-boundary-' + process.pid + '-' + Date.now());
  fs.mkdirSync(markerDir, { recursive: true });

  // Benign operation: ensure public API works and boundary can be obtained.
  const benign = new FormData();
  benign.append('field', 'value');
  const benignBoundary = benign.getBoundary();

  if (typeof benignBoundary !== 'string' || benignBoundary.length === 0) {
    throw new Error('Benign boundary not produced');
  }

  operation_completed = true;

  // Malicious check: boundary predictability due to Math.random usage.
  // For vulnerable versions, boundary consists only of decimal digits after dashes,
  // matching /^-+\d+$/, indicating non-cryptographic generation pattern.
  const samples = [];
  const sampleCount = 24;
  for (let i = 0; i < sampleCount; i++) {
    const f = new FormData();
    f.append('k', 'v');
    samples.push(f.getBoundary());
  }

  const digitOnlyPattern = /^-+\d+$/;
  const allDigitOnly = samples.every((b) => digitOnlyPattern.test(b));

  // Additional weak-entropy evidence: restricted charset across many samples.
  let charset = new Set();
  for (const b of samples) {
    for (const ch of b) charset.add(ch);
  }

  if (allDigitOnly) {
    exploit_succeeded = true;
    evidence = 'Boundaries are digit-only with dash prefix across samples, consistent with unsafe Math.random-based generation. sample=' + samples[0] + ' charset=' + Array.from(charset).sort().join('');
  } else {
    exploit_succeeded = false;
    evidence = 'Boundary generation includes broader/non-digit character patterns; unsafe predictable format not observed. sample=' + samples[0];
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Exception before completing benign operation or during setup: ' + (err && err.message ? err.message : String(err));
}

out();
