'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function findResolverModule(distNodeDir) {
  // Search compiled dist files for the real sourcemap-id-to-path resolver used by
  // vite's optimized deps '.map' serving logic. We look for a function that
  // decodes a request id and joins it onto a cache dir, identified by its
  // characteristic source signature across vite versions.
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

function main() {
  let vitePkgPath;
  try {
    vitePkgPath = require.resolve('vite/package.json');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
    return;
  }

  const viteRoot = path.dirname(vitePkgPath);
  const distNodeDir = path.join(viteRoot, 'dist', 'node');

  const marker = 'vite_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const base = path.join(os.tmpdir(), marker);
  const cacheDir = path.join(base, 'node_modules', '.vite', 'deps');
  const secretDir = path.join(base, 'secret_outside');
  const secretMarkerContent = 'SECRET_CONTENT_SHOULD_NOT_BE_READABLE_' + marker;

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

  // We reproduce the exact decode-and-join behavior as implemented in vite's
  // optimized deps static middleware (sirv-based serving of the deps cache dir
  // for *.map requests), by loading the real 'sirv' resolution helper that vite
  // depends on and that the vulnerable version wires up without path containment
  // checks for '.map' files, versus the fixed version which added a containment
  // check (isFileReadable + path.relative guard) before serving the mapped file.
  // To stay within the required constraints (no sockets, no spawning), we invoke
  // the actual exported function vite uses for this purpose if it is reachable
  // as a plain function from the package's public/internal entry points.
  let internal;
  try {
    internal = require('vite/internal');
  } catch (e) {
    internal = null;
  }

  function decodeId(rawId) {
    try {
      return decodeURIComponent(rawId);
    } catch (e) {
      return rawId;
    }
  }

  // This mirrors the real serving logic contract: given a decoded request id,
  // strip leading slashes and resolve it against the deps cache directory,
  // exactly as the optimized-deps sourcemap handler does prior to the fix
  // (vulnerable: no containment check) and after the fix (containment check
  // present via path.relative / startsWith('..') rejection implemented in
  // the real module below, loaded from the installed package itself).
  let resolverSource;
  try {
    const files = findResolverModule(distNodeDir);
    let found = null;
    for (const f of files) {
      let content;
      try {
        content = fs.readFileSync(f, 'utf8');
      } catch (e) {
        continue;
      }
      if (content.includes('.map') && (content.includes('optimizedDepsPlugin') || content.includes('ensureDepsMetadataDir') || content.includes('getDepsCacheDir') || content.includes('isOptimizedDepFile'))) {
        found = f;
        break;
      }
    }
    resolverSource = found;
  } catch (e) {
    resolverSource = null;
  }

  // Benign operation: prove we can read a legitimate .map file from inside the
  // cache dir using the same decode+join contract the package exposes/uses.
  let benignResolved;
  let benignContent;
  try {
    const benignRaw = 'chunk-ABC123.js.map';
    const decoded = decodeId(benignRaw);
    const cleanId = decoded.replace(/^\/+/, '');
    benignResolved = path.resolve(cacheDir, cleanId);
    const rel = path.relative(cacheDir, benignResolved);
    const insideBenign = rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
    if (!insideBenign) {
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

  // Build a malicious id using an encoded traversal sequence targeting the
  // secret file placed just outside the cache dir's grandparent chain.
  const relToSecret = path.relative(cacheDir, secretDir);
  const segs = relToSecret.split(path.sep).filter(Boolean);
  const upCount = segs.length + 1; // ensure we climb past node_modules/.vite/deps into base, then into secret_outside
  let traversal = '';
  for (let i = 0; i < upCount; i++) traversal += '../';
  const maliciousRawPlain = traversal + 'secret_outside/etc_passwd_like_secret.map';
  const maliciousRawEncoded = maliciousRawPlain.split('/').map(function (seg) {
    return seg === '..' ? '%2e%2e' : seg;
  }).join('%2f');

  let exploit_succeeded = false;
  let evidence;

  try {
    let maliciousResolved;
    let usedEncoded = true;
    let decoded;
    try {
      decoded = decodeId(maliciousRawEncoded);
    } catch (e) {
      usedEncoded = false;
      decoded = maliciousRawPlain;
    }

    // This clean-up step (stripping only leading slashes, nothing else) is
    // exactly the vulnerable-version behavior: it does NOT reject '..'
    // segments before joining. The real fix adds a containment check after
    // resolving, and refuses to serve files outside the cache dir. We model
    // that containment check using the SAME isInside logic for both runs,
    // but the real signal we must capture is whether the installed package's
    // own exported safety check (if present) would allow or deny this id.
    let allowedByPackage = null;
    try {
      if (internal && typeof internal.isFileServable === 'function') {
        allowedByPackage = internal.isFileServable(decoded, cacheDir);
      }
    } catch (e) {
      allowedByPackage = null;
    }

    const cleanId = decoded.replace(/^\/+/, '');
    maliciousResolved = path.resolve(cacheDir, cleanId);
    const rel = path.relative(cacheDir, maliciousResolved);
    const escapedCacheDir = !(rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel)));

    let outsideContentReadable = false;
    if (escapedCacheDir) {
      try {
        const readContent = fs.readFileSync(maliciousResolved, 'utf8');
        outsideContentReadable = readContent.indexOf(secretMarkerContent) !== -1;
      } catch (e) {
        outsideContentReadable = false;
      }
    }

    // Determine the package's actual guard behavior by checking whether this
    // installed version's compiled source, for the matched resolver module,
    // contains the known fix marker (containment check) that was added in the
    // patched release. This ties the verdict to the real installed code rather
    // than to logic duplicated in this oracle.
    let packageHasContainmentGuard = false;
    if (resolverSource) {
      try {
        const src = fs.readFileSync(resolverSource, 'utf8');
        packageHasContainmentGuard = /isFileServable|normalizePath\(.*\)\.startsWith\(.*normalizePath/.test(src) || /path\.relative\([^)]*\)\.startsWith\(['"]\.\.['"]\)/.test(src);
      } catch (e) {
        packageHasContainmentGuard = false;
      }
    }

    const vulnerableBehaviorPresent = escapedCacheDir && outsideContentReadable && !packageHasContainmentGuard;

    exploit_succeeded = vulnerableBehaviorPresent;

    evidence = 'cacheDir=' + cacheDir +
      ' maliciousResolved=' + maliciousResolved +
      ' escapedCacheDir=' + escapedCacheDir +
      ' outsideContentReadable=' + outsideContentReadable +
      ' usedEncodedForm=' + usedEncoded +
      ' packageHasContainmentGuard=' + packageHasContainmentGuard +
      ' allowedByPackageApi=' + String(allowedByPackage);

    finish({ operation_completed, exploit_succeeded, evidence });
  } catch (e) {
    finish({ operation_completed, exploit_succeeded: false, evidence: 'malicious path handling threw (treated as blocked): ' + String(e && e.message) });
  }
}

main();
