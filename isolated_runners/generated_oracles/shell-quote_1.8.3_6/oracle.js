"use strict";

var operationCompleted = false;
var exploitSucceeded = false;
var evidence = "";

function done() {
  console.log("ORACLE_RESULT " + JSON.stringify({
    operation_completed: operationCompleted,
    exploit_succeeded: exploitSucceeded,
    evidence: evidence
  }));
}

try {
  var shellQuote = require("shell-quote");
  if (!shellQuote || typeof shellQuote.quote !== "function") {
    evidence = "setup failure: shell-quote.quote is unavailable";
    done();
  } else {
    var benign;
    try {
      benign = shellQuote.quote(["alpha", "beta"]);
    } catch (e) {
      evidence = "benign call threw: " + (e && e.message ? e.message : String(e));
      done();
      return;
    }

    if (typeof benign !== "string" || benign.indexOf("alpha") === -1 || benign.indexOf("beta") === -1) {
      evidence = "benign output unexpected: " + String(benign);
      done();
      return;
    }

    operationCompleted = true;

    var marker = "SQ_NEWLINE_MARKER_9b1e2";
    var opWithNewline = "A\n" + marker + "\nB";

    try {
      var out = shellQuote.quote(["cmd", { op: opWithNewline }, "tail"]);
      if (typeof out !== "string") {
        exploitSucceeded = false;
        evidence = "malicious output non-string: " + String(out);
      } else {
        var hasRawNewline = out.indexOf("\n") !== -1;
        var hasLiteralBackslashN = out.indexOf("\\n") !== -1;
        var hasMarker = out.indexOf(marker) !== -1;

        exploitSucceeded = hasRawNewline;
        evidence = "benign=" + JSON.stringify(benign)
          + "; malicious=" + JSON.stringify(out)
          + "; has_raw_newline=" + String(hasRawNewline)
          + "; has_literal_backslash_n=" + String(hasLiteralBackslashN)
          + "; has_marker=" + String(hasMarker);
      }
    } catch (e2) {
      exploitSucceeded = false;
      evidence = "malicious blocked by exception: " + (e2 && e2.message ? e2.message : String(e2));
    }

    done();
  }
} catch (err) {
  operationCompleted = false;
  exploitSucceeded = false;
  evidence = "setup/module failure: " + (err && err.message ? err.message : String(err));
  done();
}
