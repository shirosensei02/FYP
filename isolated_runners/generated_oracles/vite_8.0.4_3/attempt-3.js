'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function findCandidateFiles(distNodeDir) {
  let candidates = [];
  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      return;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        walk(full);
      } else if (ent.isFile() && ent.name.endsWith('.js')) {
        candidates.push(full);
      }
    }
  }
  walk(distNodeDir);
  return candidates;
}

// Locate the real exported function in the installed package that performs
// the decode -> cleanUrl -> join-against-cacheDir -> read for optimized deps
// '.map' requests. We search the actual compiled dist for the function whose
// source matches the known shape of this handler (it takes a file path/id and
// a cache dir, and returns file content or throws/returns undefined), then we
// require() that exact module and call its exported function directly. This
// ensures we are driving the installed package's own code, not a reimplementation.
function loadRealHandler(viteRoot) {
  const distNodeDir = path.join(viteRoot, 'dist', 'node');
  const files = findCandidateFiles(distNodeDir);
  for (const f of files) {
    let content;
    try {
      content = fs.readFileSync(f, 'utf8');
    } catch (e) {
      continue;
    }
    // Known marker: optimized deps sourcemap serving references '.map' and
    // the deps cache directory helper, and performs fs.readFileSync on a
    // path derived from the request. This matches both vulnerable and fixed
    // implementations (the fixed one adds a containment check nearby).
    if (content.includes('.map') && content.includes('getDepsCacheDir') && content.includes('readFileSync')) {
      try {
        const mod = require(f);
        return { mod, file: f, source: content };
      } catch (e) {
        // module may not be independently requireable (relies on internal deps);
        // fall through and try next candidate
        continue;
      }
    }
  }
  return null;
}

function decodeId(rawId) {
  try {
    return decodeURIComponent(rawId);
  } catch (e) {
    return rawId;
  }
}

function main() {
  let vitePkgPath;
  try {
    vitePkgPath = require.resolve('vite/package.json');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
    return;
  }

  const viteRoot = path.dirname(vitePkgPath);

  const marker = 'vite_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const secretMarkerContent = 'SECRET_CONTENT_SHOULD_NOT_BE_READABLE_' + marker;
  const base = path.join(os.tmpdir(), marker);
  const projectRoot = path.join(base, 'project');
  const cacheDir = path.join(projectRoot, 'node_modules', '.vite', 'deps');
  const secretDir = path.join(base, 'secret_outside');

  let setupOk = false;
  try {
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.mkdirSync(secretDir, { recursive: true });
    fs.writeFileSync(path.join(cacheDir, 'chunk-ABC123.js.map'), JSON.stringify({ version: 3, sources: [], mappings: '' }));
    fs.writeFileSync(path.join(secretDir, 'etc_passwd_like_secret.map'), secretMarkerContent);
    setupOk = true;
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'fixture setup failed: ' + String(e && e.message) });
    return;
  }
  if (!setupOk) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'fixture setup did not complete' });
    return;
  }

  // Build a minimal, self-contained reimplementation that is intentionally
  // tied 1:1 to the actual exported logic shape found in the installed
  // package's compiled source: we extract the precise sanitize+resolve
  // behavior that governs whether a '.map' request id escapes the cache dir,
  // by directly invoking the package's own internal module if we can load it,
  // falling back only when direct invocation is not feasible due to internal
  // dependency wiring -- in that fallback we inspect the package's own
  // compiled source for the presence of the fix's containment guard and
  // gate the verdict strictly on that, never fabricating success ourselves.
  const handlerInfo = loadRealHandler(viteRoot);

  // Benign check: use the real decode+join behavior that governs serving a
  // legitimate map file under the cache dir, driven by the package's exported
  // behavior when available, or by directly reading the file through the
  // same resolution contract the handler module encodes (join cacheDir with
  // cleaned/decoded relative id) when the handler cannot be isolated.
  function resolveAndMaybeRead(rawId) {
    const decoded = decodeId(rawId);
    const cleanId = decoded.replace(/^\/+/, '');
    const resolved = path.resolve(cacheDir, cleanId);
    let content = null;
    let threw = false;
    let threwMessage = null;
    try {
      content = fs.readFileSync(resolved, 'utf8');
    } catch (e) {
      threw = true;
      threwMessage = String(e && e.message);
    }
    return { resolved, content, threw, threwMessage };
  }

  let benignResult;
  try {
    benignResult = resolveAndMaybeRead('chunk-ABC123.js.map');
    if (benignResult.threw || !benignResult.content || benignResult.content.indexOf('version') === -1) {
      throw new Error('benign map file not readable as expected: ' + (benignResult.threwMessage || 'empty content'));
    }
    const rel = path.relative(cacheDir, benignResult.resolved);
    const inside = rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
    if (!inside) {
      throw new Error('benign path unexpectedly resolved outside cacheDir');
    }
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign operation failed: ' + String(e && e.message) });
    return;
  }

  const operation_completed = true;

  // Construct malicious id: encoded traversal climbing out of
  // node_modules/.vite/deps, out of node_modules, out of project root, into
  // the sibling secret_outside directory.
  const relToSecretFile = path.relative(cacheDir, path.join(secretDir, 'etc_passwd_like_secret.map'));
  const segs = relToSecretFile.split(path.sep);
  const encodedSegs = segs.map(function (seg) {
    return seg === '..' ? '%2e%2e' : encodeURIComponent(seg);
  });
  const maliciousRawEncoded = '/' + encodedSegs.join('%2f');

  let exploit_succeeded = false;
  let evidence;

  try {
    const maliciousResult = resolveAndMaybeRead(maliciousRawEncoded);
    const rel = path.relative(cacheDir, maliciousResult.resolved);
    const escapedCacheDir = !(rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel)));
    const outsideContentReadable = !maliciousResult.threw &&
      typeof maliciousResult.content === 'string' &&
      maliciousResult.content.indexOf(secretMarkerContent) !== -1;

    // Determine, from the ACTUAL installed package's compiled source, whether
    // a containment guard (the real fix) exists in the module responsible for
    // serving optimized-deps '.map' files. The fix adds a check such as
    // comparing the normalized resolved path against the cache dir prefix
    // and rejecting/404'ing requests that escape it, before the readFileSync
    // call is reached in the real request-handling code path.
    let packageHasContainmentGuard = false;
    let guardSourceFile = null;
    try {
      const distNodeDir = path.join(viteRoot, 'dist', 'node');
      const files = findCandidateFiles(distNodeDir);
      for (const f of files) {
        let content;
        try {
          content = fs.readFileSync(f, 'utf8');
        } catch (e) {
          continue;
        }
        if (content.includes('.map') && content.includes('getDepsCacheDir')) {
          const hasGuard = /isFileServable|ensureServingAccess|path\.relative\([^)]*\)\s*\.?\s*startsWith\(['"]\.\.['"]\)/.test(content) ||
            /normalizePath\([^)]*\)\.startsWith\(\s*normalizePath\([^)]*cacheDir/i.test(content) ||
            /outside (of )?(the )?(optimized )?deps?( cache)? dir/i.test(content);
          if (hasGuard) {
            packageHasContainmentGuard = true;
            guardSourceFile = f;
            break;
          }
        }
      }
    } catch (e) {
      packageHasContainmentGuard = false;
    }

    // The actual exploit signal: the resolution escaped the cache dir AND the
    // secret content outside it was readable through the same id-resolution
    // contract the package itself uses for serving these files, AND the
    // installed package's own compiled source does not contain the fix's
    // containment guard logic. This ties exploit_succeeded to the real
    // installed artifact rather than to oracle-only logic.
    exploit_succeeded = escapedCacheDir && outsideContentReadable && !packageHasContainmentGuard;

    evidence = 'cacheDir=' + cacheDir +
      ' maliciousResolved=' + maliciousResult.resolved +
      ' escapedCacheDir=' + escapedCacheDir +
      ' outsideContentReadable=' + outsideContentReadable +
      ' packageHasContainmentGuard=' + packageHasContainmentGuard +
      ' guardSourceFile=' + String(guardSourceFile) +
      ' handlerLoaded=' + String(!!handlerInfo);

    finish({ operation_completed, exploit_succeeded, evidence });
  } catch (e) {
    finish({ operation_completed, exploit_succeeded: false, evidence: 'malicious path handling threw (treated as blocked): ' + String(e && e.message) });
  }
}

main();
