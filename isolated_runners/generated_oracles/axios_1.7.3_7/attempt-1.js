const http = require('http');
const axios = require('axios');

(async () => {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  let server;
  try {
    let benignHits = 0;
    let secretHits = 0;
    let otherHits = 0;

    server = http.createServer((req, res) => {
      if (req.url === '/benign') {
        benignHits += 1;
        res.statusCode = 200;
        res.end('benign-ok');
        return;
      }
      if (req.url === '/secret') {
        secretHits += 1;
        res.statusCode = 200;
        res.end('secret-ok');
        return;
      }
      otherHits += 1;
      res.statusCode = 404;
      res.end('not-found');
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });

    const addr = server.address();
    const port = addr.port;
    const baseURL = `http://127.0.0.1:${port}`;

    const benignResp = await axios.get('/benign', {
      baseURL,
      timeout: 2000,
      proxy: false
    });

    if (!benignResp || benignResp.status !== 200 || benignResp.data !== 'benign-ok' || benignHits < 1) {
      throw new Error('Benign operation did not complete as expected');
    }

    operation_completed = true;

    try {
      await axios.get(`http://127.0.0.1:${port}/secret`, {
        baseURL,
        allowAbsoluteUrls: false,
        timeout: 2000,
        proxy: false,
        validateStatus: () => true
      });
    } catch (e) {
      // Exception after benign success counts as blocked unless secret endpoint was reached.
    }

    exploit_succeeded = secretHits > 0;
    evidence = JSON.stringify({ benignHits, secretHits, otherHits, baseURL });
  } catch (err) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = `setup_or_benign_failure:${err && err.message ? err.message : String(err)}`;
  } finally {
    if (server) {
      await new Promise((resolve) => server.close(() => resolve()));
    }
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
  }
})();