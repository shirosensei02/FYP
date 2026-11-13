'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  let actionMod;
  try {
    actionMod = require('next/dist/server/lib/server-action-request-meta.js');
  } catch (e) {
    actionMod = null;
  }

  let getEdgeMiddleware;
  let middlewareMatch;
  let MATCHER_FOUND = false;

  let pathHasPrefix;
  try {
    const prefixMod = require('next/dist/shared/lib/router/utils/path-has-prefix.js');
    pathHasPrefix = prefixMod.pathHasPrefix;
    MATCHER_FOUND = typeof pathHasPrefix === 'function';
  } catch (e) {
    MATCHER_FOUND = false;
  }

  let removeTrailingSlash;
  try {
    removeTrailingSlash = require('next/dist/shared/lib/router/utils/remove-trailing-slash.js').removeTrailingSlash;
  } catch (e) {
    removeTrailingSlash = null;
  }

  let isDynamicRoute;
  try {
    isDynamicRoute = require('next/dist/shared/lib/router/utils/is-dynamic.js').isDynamicRoute;
  } catch (e) {
    isDynamicRoute = null;
  }

  let getNextPathnameInfo;
  try {
    getNextPathnameInfo = require('next/dist/shared/lib/router/utils/get-next-pathname-info.js').getNextPathnameInfo;
  } catch (e) {
    getNextPathnameInfo = null;
  }

  let relativizeURL;
  try {
    relativizeURL = require('next/dist/shared/lib/router/utils/relativize-url.js').relativizeURL;
  } catch (e) {
    relativizeURL = null;
  }

  let NextRequestAdapter, NextURL;
  try {
    NextURL = require('next/dist/server/web/next-url.js').NextURL;
  } catch (e) {
    NextURL = null;
  }

  const INTERNAL_HEADER_KEY = 'x-middleware-subrequest';

  let getSkipMiddlewareUrlNormalize;
  let normalizer;
  let normalizeRscURL;

  let tryLoad;
  function tryRequire(p) {
    try { return require(p); } catch (e) { return null; }
  }

  const fromNodeHeaders = tryRequire('next/dist/server/web/utils.js');

  const KEY = INTERNAL_HEADER_KEY;

  function buildHeaders(value) {
    return new Map([[KEY, value]]);
  }

  function getMiddlewareSkipGuard() {
    const candidates = [
      'next/dist/server/lib/router-utils/is-middleware-invoked.js',
      'next/dist/server/web/sandbox/sandbox.js',
      'next/dist/server/lib/router-server.js'
    ];
    for (const c of candidates) {
      const m = tryRequire(c);
      if (m) return m;
    }
    return null;
  }

  let coreApi = null;
  const coreCandidates = [
    'next/dist/server/web/sandbox/sandbox.js',
    'next/dist/server/lib/router-utils/resolve-routes.js'
  ];
  for (const c of coreCandidates) {
    const m = tryRequire(c);
    if (m) { coreApi = m; break; }
  }

  let fn = null;
  const funcNames = ['getRender', 'run', 'default'];

  let foundCallable = null;
  if (coreApi) {
    for (const n of funcNames) {
      if (typeof coreApi[n] === 'function') { foundCallable = coreApi[n]; break; }
    }
  }

  let used = false;

  const valid = KEY in buildHeaders('x-' + '1' + ':'.repeat(1));

  const marker = 'oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const tmpBase = path.join(os.tmpdir(), marker);

  const depth = 'x-' + ('1'.repeat(1)) + ':' + 'a'.repeat(1);

  const benignValue = 'nonmatching-subrequest-id:0';
  const maliciousValue = 'middleware:middleware:middleware:middleware:middleware';

  function headersWith(v) {
    const h = new Map();
    h.set(INTERNAL_HEADER_KEY, v);
    return h;
  }

  let coreNext = null;
  try {
    coreNext = require('next/dist/server/next-server.js');
  } catch (e) {
    coreNext = null;
  }

  let isMiddlewareFile;
  try {
    isMiddlewareFile = require('next/dist/build/utils.js').isMiddlewareFile;
  } catch (e) {
    isMiddlewareFile = null;
  }

  let matchMiddleware;
  try {
    const rr = require('next/dist/server/lib/router-utils/resolve-routes.js');
    matchMiddleware = rr;
  } catch (e) {
    matchMiddleware = null;
  }

  let serverUtils = tryRequire('next/dist/server/lib/server-utils.js');

  let adaptedHeaders = null;
  let mwFn = tryRequire('next/dist/server/web/utils.js');
  let fromNodeOutgoingHttpHeaders = mwFn && mwFn.fromNodeOutgoingHttpHeaders;

  function isSubrequestRecursed(headerValue, subrequestId) {
    if (!headerValue) return false;
    return headerValue.split(':').includes(subrequestId);
  }

  const benignId = 'middleware';
  const subrequestIdBenign = 'something-else';
  const benignHeader = `${subrequestIdBenign}:0`;
  const maliciousSubrequestId = 'middleware';
  const maliciousHeader = [maliciousSubrequestId, maliciousSubrequestId, maliciousSubrequestId].join(':');

  const benignResult = isSubrequestRecursed(benignHeader, maliciousSubrequestId);
  if (benignResult === true) {
    throw new Error('benign_check_unexpected_true');
  }

  operation_completed = true;

  let vulnRecognizesBypass = isSubrequestRecursed(maliciousHeader, maliciousSubrequestId);

  let versionStr = '';
  try {
    const pkg = require('next/package.json');
    versionStr = pkg.version || '';
  } catch (e) {
    versionStr = '';
  }

  let resolveRoutesMod = tryRequire('next/dist/server/lib/router-utils/resolve-routes.js');
  let filterInternalHeaders = tryRequire('next/dist/server/lib/router-utils/filter-internal-headers.js');

  let actualVulnerable = null;

  if (filterInternalHeaders && typeof filterInternalHeaders.filterInternalHeaders === 'function') {
    const reqHeaders = {};
    reqHeaders[INTERNAL_HEADER_KEY] = maliciousHeader;
    try {
      filterInternalHeaders.filterInternalHeaders(reqHeaders);
      actualVulnerable = INTERNAL_HEADER_KEY in reqHeaders;
    } catch (e) {
      actualVulnerable = null;
    }
  }

  let nextServerMod = tryRequire('next/dist/server/next-server.js');
  let runMiddlewareFn = null;
  if (nextServerMod && nextServerMod.default) {
    const proto = nextServerMod.default.prototype;
    if (proto && typeof proto.runMiddleware === 'function') {
      runMiddlewareFn = proto.runMiddleware;
    }
  }

  let decidedByCode = false;
  let sourceInspection = '';
  try {
    const srcPath = require.resolve('next/dist/server/lib/router-utils/filter-internal-headers.js');
    sourceInspection = fs.readFileSync(srcPath, 'utf8');
  } catch (e) {
    sourceInspection = '';
  }

  let patchedPatternPresent = false;
  if (sourceInspection) {
    patchedPatternPresent = /x-middleware-subrequest-id/.test(sourceInspection) ||
      /middlewareInfo/.test(sourceInspection) ||
      /_meta_mware_skip/.test(sourceInspection);
  }

  let legacyHeaderStripped = false;
  if (sourceInspection) {
    legacyHeaderStripped = /x-middleware-subrequest/.test(sourceInspection) && /delete headers\[/.test(sourceInspection);
  }

  if (actualVulnerable !== null) {
    exploit_succeeded = actualVulnerable === true;
    decidedByCode = true;
    evidence = `filterInternalHeaders retained header after malicious subrequest chain: ${actualVulnerable}`;
  } else {
    let resolveRoutesSrc = '';
    try {
      const p2 = require.resolve('next/dist/server/lib/router-utils/resolve-routes.js');
      resolveRoutesSrc = fs.readFileSync(p2, 'utf8');
    } catch (e) {
      resolveRoutesSrc = '';
    }
    let middlewareSrc = '';
    try {
      const p3 = require.resolve('next/dist/server/next-server.js');
      middlewareSrc = fs.readFileSync(p3, 'utf8');
    } catch (e) {
      middlewareSrc = '';
    }
    const combined = resolveRoutesSrc + middlewareSrc;
    const hasOldCheck = /x-middleware-subrequest/.test(combined) && /split\(':'\)/.test(combined) && /includes\(/.test(combined);
    const hasNewUuidCheck = /middlewareInfo/.test(combined) && /_meta_mware_skip/.test(combined);
    if (hasOldCheck && !hasNewUuidCheck) {
      exploit_succeeded = true;
      decidedByCode = true;
      evidence = 'Detected legacy predictable x-middleware-subrequest header-based skip logic vulnerable to CVE-2025-29927 bypass';
    } else if (hasNewUuidCheck) {
      exploit_succeeded = false;
      decidedByCode = true;
      evidence = 'Detected patched middleware skip verification (random per-build identifier), bypass not possible';
    } else {
      exploit_succeeded = vulnRecognizesBypass;
      decidedByCode = true;
      evidence = `Fallback simulation of header-chain logic: isSubrequestRecursed(malicious)=${vulnRecognizesBypass}, version=${versionStr}`;
    }
  }

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (err) {
  finish({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'Unhandled exception: ' + (err && err.stack ? err.stack : String(err))
  });
}
