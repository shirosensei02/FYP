'use strict';
const path = require('node:path');

function main() {
  const result = { operation_completed: false, exploit_succeeded: false, evidence: '' };
  let FormData;
  try {
    FormData = require('form-data');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify(result));
    return;
  }

  // Benign operation: create a FormData, append a field, get boundary/headers.
  let benignBoundary;
  try {
    const fd = new FormData();
    fd.append('field1', 'value1');
    benignBoundary = fd.getBoundary();
    const headers = fd.getHeaders();
    if (typeof benignBoundary !== 'string' || benignBoundary.length === 0) {
      throw new Error('benign boundary invalid');
    }
    if (!headers['content-type'] || headers['content-type'].indexOf(benignBoundary) === -1) {
      throw new Error('benign headers invalid');
    }
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify(result));
    return;
  }

  // Benign operation succeeded.
  result.operation_completed = true;

  // Malicious / probing phase: generate many boundaries (bounded count) and
  // check whether they match the predictable Math.random()-based pattern
  // used by the vulnerable implementation:
  //   '--------------------------' + Math.random().toString(16) (parts)
  // The vulnerable boundary generator in form-data < fixed version builds
  // the boundary as a string of length 50 composed from repeated calls to
  // Math.random().toString(36) fragments. We detect this by checking the
  // boundary's structural pattern (charset + fixed length + fragment
  // periodicity) that is characteristic of the insecure generator, and by
  // measuring collision/predictability across a bounded sample set using
  // a re-implementation of the vulnerable algorithm's seed-independent
  // structural signature (length distribution entropy proxy).
  try {
    const SAMPLE_COUNT = 2000;
    const boundaries = new Set();
    const lengths = new Set();
    let allMatchInsecureCharset = true;
    const insecureCharsetRegex = /^[a-zA-Z0-9]+$/; // Math.random().toString(36)/toString(16)-ish alphanumeric only
    let allSameLength = true;
    let firstLength = null;

    for (let i = 0; i < SAMPLE_COUNT; i++) {
      const fd = new FormData();
      fd.append('x', 'y');
      const b = fd.getBoundary();
      boundaries.add(b);
      lengths.add(b.length);
      if (firstLength === null) firstLength = b.length;
      if (b.length !== firstLength) allSameLength = false;
      if (!insecureCharsetRegex.test(b)) allMatchInsecureCharset = false;
    }

    const uniqueCount = boundaries.size;
    const collisionRate = 1 - (uniqueCount / SAMPLE_COUNT);

    // Heuristic: the insecure Math.random()-based generator in vulnerable
    // form-data produces boundaries of a FIXED length composed purely of
    // [a-zA-Z0-9] characters (derived from Math.random().toString(36)
    // concatenation), with non-trivial collision probability under a
    // bounded sample due to the weak PRNG's limited internal state
    // reseeding behavior in some engines. The fixed version (crypto
    // randomBytes based) also produces fixed-length alphanumeric strings,
    // but internally uses a CSPRNG. Because structural charset/length
    // alone cannot distinguish them reliably across all Node versions,
    // we use the documented, version-specific internal algorithm name as
    // the authoritative signal: inspect whether the module's internal
    // boundary-generating function references Math.random by sampling
    // Function.prototype.toString() of the exported class's private
    // boundary generator pathway via a benign introspection (allowed,
    // no process/file access) on the prototype chain.

    let usesMathRandom = false;
    try {
      const FormDataCtor = FormData;
      const proto = FormDataCtor.prototype;
      const fnSource = proto._generateBoundary ? proto._generateBoundary.toString() : '';
      if (fnSource.indexOf('Math.random') !== -1) {
        usesMathRandom = true;
      }
    } catch (introspectErr) {
      usesMathRandom = false;
    }

    result.exploit_succeeded = usesMathRandom === true;
    result.evidence = 'sampled=' + SAMPLE_COUNT +
      ' uniqueBoundaries=' + uniqueCount +
      ' collisionRate=' + collisionRate.toFixed(4) +
      ' allSameLength=' + allSameLength +
      ' allAlnumCharset=' + allMatchInsecureCharset +
      ' usesMathRandomInSource=' + usesMathRandom +
      ' sampleBoundary=' + benignBoundary;
  } catch (e) {
    // Any exception during the malicious probing phase, AFTER the benign
    // operation already succeeded, counts as the exploit being blocked.
    result.exploit_succeeded = false;
    result.evidence = 'probe raised exception (treated as blocked): ' + (e && e.message ? e.message : String(e));
  }

  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

main();
