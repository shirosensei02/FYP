'use strict';

function main() {
  let axios;
  try {
    axios = require('axios');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Failed to require axios: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  // Create an axios instance scoped to a trusted base host, with
  // allowAbsoluteUrls explicitly set to false. This is the documented,
  // public configuration surface that applications use to prevent
  // requests from escaping a trusted baseURL (SSRF mitigation).
  let instance;
  try {
    instance = axios.create({
      baseURL: 'http://trusted-internal.example.com/api/',
      allowAbsoluteUrls: false
    });
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Failed to create axios instance: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  if (!instance || typeof instance.getUri !== 'function') {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'axios instance missing getUri method; cannot exercise public API'
    }));
    return;
  }

  // --- Benign case: relative path combined with baseURL should resolve
  // to a URL scoped under the trusted host. ---
  let benignResult;
  try {
    benignResult = instance.getUri({ url: '/users/list' });
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign getUri call threw: ' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  const benignOk = typeof benignResult === 'string' &&
    benignResult.indexOf('trusted-internal.example.com') !== -1 &&
    benignResult.indexOf('/users/list') !== -1;

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign getUri result unexpected: ' + String(benignResult)
    }));
    return;
  }

  operation_completed = true;

  // --- Malicious case: an attacker-controlled absolute URL is supplied
  // as the request url while the application has explicitly disallowed
  // absolute URLs via allowAbsoluteUrls=false, intending every request
  // issued through this instance to remain confined to the trusted
  // baseURL host. In the vulnerable version, the allowAbsoluteUrls
  // option is not honored by the resolution path used by getUri/request,
  // so the attacker-supplied absolute URL is used verbatim, bypassing
  // the baseURL confinement entirely (SSRF). In the patched version,
  // when allowAbsoluteUrls is explicitly false, the absolute URL is
  // rejected (throws) or combined so the result stays scoped to the
  // trusted base host.
  const maliciousAbsolute = 'http://attacker.test/evil';

  let maliciousResult;
  let threw = false;
  let errMsg = '';
  try {
    maliciousResult = instance.getUri({ url: maliciousAbsolute });
  } catch (e) {
    threw = true;
    errMsg = e && e.message ? e.message : String(e);
  }

  if (threw) {
    exploit_succeeded = false;
    evidence = 'Malicious getUri call with allowAbsoluteUrls=false threw an exception, indicating the bypass was blocked: ' + errMsg;
  } else {
    const pointsToAttacker = typeof maliciousResult === 'string' &&
      maliciousResult.indexOf('attacker.test') !== -1;
    const staysOnBase = typeof maliciousResult === 'string' &&
      maliciousResult.indexOf('trusted-internal.example.com') !== -1;

    if (pointsToAttacker && !staysOnBase) {
      exploit_succeeded = true;
      evidence = 'getUri with allowAbsoluteUrls=false still honored the absolute attacker URL, bypassing baseURL confinement. Result: ' + String(maliciousResult);
    } else {
      exploit_succeeded = false;
      evidence = 'getUri with allowAbsoluteUrls=false kept the request scoped to baseURL, rejecting the attacker absolute URL. Result: ' + String(maliciousResult);
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed,
    exploit_succeeded,
    evidence
  }));
}

try {
  main();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'Unhandled exception in oracle script: ' + (e && e.message ? e.message : String(e))
  }));
}
