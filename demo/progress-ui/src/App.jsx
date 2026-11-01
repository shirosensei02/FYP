import { useEffect, useState } from "react";
import { useStream } from "@langchain/langgraph-sdk/react";

const API_URL = import.meta.env.VITE_LANGGRAPH_URL ?? "http://localhost:2024";

// Pipeline order of the `demo` graph (demo_graph.py); titles match its progress entries.
const STEPS = [
  { id: "package_input_node", title: "📦 Package input" },
  { id: "vulnerability_detection_node", title: "🔍 Vulnerability detection" },
  { id: "og_patch_resolution_node", title: "📚 Maintainer fix lookup" },
  { id: "patch_generation_node", title: "🤖 Patch generation" },
  { id: "patch_application_node", title: "🐳 Sandbox build" },
  { id: "vulnerability_rescan_node", title: "🔁 Rescan" },
  { id: "adversarial_evaluation_node", title: "🧑‍⚖️ Independent review" },
  { id: "patch_validation_node", title: "🏁 Validation" },
  { id: "patch_scoring_node", title: "📐 Scoring" },
  { id: "maintainer_eval_node", title: "📝 Maintainer comparison" },
];

const MODELS = [
  { label: "GPT-5.3 Codex", value: "openai/gpt-5.3-codex" },
  { label: "Claude Sonnet 5", value: "anthropic/claude-sonnet-5" },
];

const EXAMPLES = [
  { package_name: "jszip", package_version: "3.7.1", vulnerability_id: "GHSA-36fh-84j7-cv5h" },
  { package_name: "tar-fs", package_version: "3.0.8", vulnerability_id: "GHSA-8cj5-5rvv-wf4v" },
  { package_name: "joi", package_version: "18.2.5", vulnerability_id: "GHSA-6h2x-m376-mqjq" },
];

export default function App() {
  const stream = useStream({ apiUrl: API_URL, assistantId: "demo" });
  const [form, setForm] = useState({ ...EXAMPLES[0], model_name: MODELS[0].value });
  const [stepStartedAt, setStepStartedAt] = useState(null);
  const [now, setNow] = useState(Date.now());

  const values = stream.values ?? {};
  const progress = (values.progress ?? []).filter((entry) => entry.step !== "demo_input");
  const settings = (values.progress ?? []).find((entry) => entry.step === "demo_input");
  const running = stream.isLoading;
  const finished = !running && progress.length > 0;

  // The step that is currently running started when the previous one finished.
  useEffect(() => {
    if (running) setStepStartedAt(Date.now());
  }, [running, progress.length]);

  useEffect(() => {
    if (!running) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(timer);
  }, [running]);

  const startRun = (event) => {
    event.preventDefault();
    stream.switchThread(null); // every run gets a fresh thread
    stream.submit({
      package_name: form.package_name.trim(),
      package_version: form.package_version.trim(),
      vulnerability_id: form.vulnerability_id.trim() || null,
      model_name: form.model_name,
    });
  };

  const seen = new Set(progress.map((entry) => entry.step));
  const remaining = STEPS.filter((step) => !seen.has(step.id));

  return (
    <div className="page">
      <header>
        <h1>LLM Security Patch Pipeline</h1>
        <p>Detect a known npm vulnerability, let a model patch it, and check the patch in a sandbox.</p>
      </header>

      <form className="card run-form" onSubmit={startRun}>
        <label>
          Package
          <input value={form.package_name} onChange={(e) => setForm({ ...form, package_name: e.target.value })} required />
        </label>
        <label>
          Version
          <input value={form.package_version} onChange={(e) => setForm({ ...form, package_version: e.target.value })} required />
        </label>
        <label>
          Advisory ID <span className="hint">(optional)</span>
          <input value={form.vulnerability_id} onChange={(e) => setForm({ ...form, vulnerability_id: e.target.value })} />
        </label>
        <label>
          Model
          <select value={form.model_name} onChange={(e) => setForm({ ...form, model_name: e.target.value })}>
            {MODELS.map((model) => (
              <option key={model.value} value={model.value}>{model.label}</option>
            ))}
          </select>
        </label>
        <div className="form-actions">
          <div className="examples">
            Examples:
            {EXAMPLES.map((example) => (
              <button type="button" key={example.package_name} className="link" disabled={running}
                onClick={() => setForm({ ...form, ...example })}>
                {example.package_name}@{example.package_version}
              </button>
            ))}
          </div>
          {running ? (
            <button type="button" className="secondary" onClick={() => stream.stop()}>Stop</button>
          ) : (
            <button type="submit">Run pipeline</button>
          )}
        </div>
      </form>

      {stream.error ? <div className="card error">Could not reach the pipeline server at {API_URL}: {String(stream.error)}</div> : null}
      {values.input_error ? <div className="card error">{values.input_error}</div> : null}
      {settings ? <div className="settings"><Rich text={settings.summary} /></div> : null}

      {(running || progress.length > 0) && (
        <ol className="steps">
          {progress.map((entry, index) => (
            <Step key={`${entry.step}-${index}`} status="done" title={entry.title} seconds={entry.seconds} summary={entry.summary} />
          ))}
          {remaining.map((step, index) => {
            const status = running ? (index === 0 ? "running" : "pending") : "skipped";
            const seconds = status === "running" && stepStartedAt ? (now - stepStartedAt) / 1000 : null;
            return <Step key={step.id} status={status} title={step.title} seconds={seconds} />;
          })}
        </ol>
      )}

      {finished && values.classification ? <Outcome values={values} /> : null}
    </div>
  );
}

function Step({ status, title, seconds, summary }) {
  const icon = { done: "✓", running: "", pending: "", skipped: "–" }[status];
  return (
    <li className={`step ${status}`}>
      <div className="step-head">
        <span className="badge">{status === "running" ? <span className="spinner" /> : icon}</span>
        <span className="step-title">{title}</span>
        {seconds != null ? <span className="seconds">{seconds.toFixed(0)}s</span> : null}
        {status === "skipped" ? <span className="seconds">not run</span> : null}
      </div>
      {summary ? <div className="step-body"><Rich text={summary} /></div> : null}
    </li>
  );
}

function Outcome({ values }) {
  const passed = values.classification === "pass";
  const review = values.adversarial_evaluation?.genuine_fix;
  const comparison = values.maintainer_eval?.verdict;
  return (
    <div className={`card outcome ${passed ? "pass" : "fail"}`}>
      <div className="outcome-title">{passed ? "PASS" : "FAIL"}</div>
      <div>{values.classification_reason}</div>
      <div className="outcome-facts">
        <span>Independent review: <strong>{review ?? "n/a"}</strong></span>
        <span>Vs maintainer fix: <strong>{comparison ?? "n/a"}</strong></span>
      </div>
    </div>
  );
}

// Minimal renderer for the step summaries: ``` code blocks, **bold** and `code`.
function Rich({ text }) {
  const parts = text.split(/```(\w*)\n([\s\S]*?)```/g);
  const nodes = [];
  for (let i = 0; i < parts.length; i += 3) {
    if (parts[i]) nodes.push(<Inline key={`t${i}`} text={parts[i]} />);
    if (i + 2 < parts.length) {
      nodes.push(
        <pre key={`c${i}`} className={`code ${parts[i + 1]}`}>
          {parts[i + 2].split("\n").map((line, n) => (
            <div key={n} className={line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : ""}>
              {line || " "}
            </div>
          ))}
        </pre>,
      );
    }
  }
  return <>{nodes}</>;
}

function Inline({ text }) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((piece, index) => {
    if (piece.startsWith("**") && piece.endsWith("**")) return <strong key={index}>{piece.slice(2, -2)}</strong>;
    if (piece.startsWith("`") && piece.endsWith("`")) return <code key={index}>{piece.slice(1, -1)}</code>;
    return <span key={index}>{piece}</span>;
  });
}
