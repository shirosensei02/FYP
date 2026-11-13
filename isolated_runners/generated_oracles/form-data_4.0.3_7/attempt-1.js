const FormData = require('form-data');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  const result = { operation_completed, exploit_succeeded, evidence };
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  // Benign operation first
  const benignForm = new FormData();
  const benignBoundary = benignForm.getBoundary();

  if (typeof benignBoundary !== 'string' || benignBoundary.length === 0) {
    throw new Error('benign getBoundary() did not return non-empty string');
  }

  // Mark operation as completed only after benign succeeds
  operation_completed = true;

  // Malicious/probing input: bounded statistical probe
  const SAMPLE_SIZE = 400;
  const seen = new Set();
  let duplicates = 0;
  let weakFormatCount = 0;
  let total = 0;

  for (let i = 0; i < SAMPLE_SIZE; i++) {
    const f = new FormData();
    const b = f.getBoundary();
    total++;

    if (seen.has(b)) {
      duplicates++;
    } else {
      seen.add(b);
    }

    // form-data boundaries commonly start with many dashes then random suffix.
    // Vulnerable implementation uses repeated decimal digits from Math.random().
    const m = /^-+([0-9]+)$/.exec(b);
    if (m) {
      // strong weak-signal: suffix is decimal-only and reasonably long
      if (m[1].length >= 16) {
        weakFormatCount++;
      }
    }
  }

  // Conservative exploit criteria:
  // 1) Nearly all sampled boundaries match weak decimal-only suffix pattern.
  // 2) Any duplicate strengthens confidence, but not strictly required.
  const weakFormatRatio = weakFormatCount / total;
  exploit_succeeded = weakFormatRatio > 0.95;

  evidence = JSON.stringify({
    sample_size: SAMPLE_SIZE,
    unique: seen.size,
    duplicates,
    weak_format_count: weakFormatCount,
    weak_format_ratio: Number(weakFormatRatio.toFixed(4)),
    benign_boundary_example: benignBoundary.slice(0, 40)
  });

  out();
} catch (err) {
  if (!operation_completed) {
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error: ' + (err && err.message ? err.message : String(err));
  } else {
    // Malicious-path exception after benign success counts as blocked
    exploit_succeeded = false;
    evidence = 'malicious_call_blocked_or_failed: ' + (err && err.message ? err.message : String(err));
  }
  out();
}