#!/usr/bin/env bash
# Run LangChain's Agent Chat UI against the local LangGraph server (`langgraph dev`).
#
# Usage (from the repo root, with `langgraph dev` already running in another terminal):
#   bash demo/start_chat_ui.sh
# Then open http://localhost:3000 and send e.g. `jszip@3.7.1 GHSA-36fh-84j7-cv5h codex`.
set -euo pipefail

UI_REPO="https://github.com/langchain-ai/agent-chat-ui.git"
UI_COMMIT="2624b821a4542e115a7e8eb8917e4cfb42397ce6"  # pinned so the demo does not change underneath us
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UI_DIR="$ROOT/demo/agent-chat-ui"

if [ ! -d "$UI_DIR/.git" ]; then
  git clone --quiet "$UI_REPO" "$UI_DIR"
  git -C "$UI_DIR" checkout --quiet "$UI_COMMIT"
fi

# Skip the setup form: point the UI at the local server and the `demo` graph.
cat > "$UI_DIR/.env" <<ENV
NEXT_PUBLIC_API_URL=http://localhost:2024
NEXT_PUBLIC_ASSISTANT_ID=demo
NEXT_PUBLIC_AUTH_SCHEME=
ENV

cd "$UI_DIR"
pnpm install
pnpm dev
