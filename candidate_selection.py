"""Choose one patch from several samples by running the accepted oracle on each.

Agentless (Xia et al., FSE 2025) samples many patches and picks one with a
reproduction test. Here the locked security oracle is that test: every distinct
candidate is applied to a throwaway copy of the vulnerable package and the
exploit is run against it. A patch that blocks the exploit beats one that does
not; ties go to the largest cluster of identical samples, then the smallest diff.

The chosen patch then flows through the normal apply -> locked oracle -> package
validation path, so this node only decides which candidate that path sees. It
never changes how a verdict is reached.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from cost_log import diff_line_counts
from oracle_validation import _run_oracle, classify_patch_execution
from patch_application import PATCH_WORKSPACE_ROOT, _seed_workspace_from_source, _write_patched_package
from state import CandidateSelection, GraphState

logger = logging.getLogger(__name__)

ORACLE_WORKERS = max(1, int(os.getenv("CANDIDATE_ORACLE_WORKERS", "2")))
# Lower is better. A patch that breaks the package is worse than one that
# leaves the exploit working; an inconclusive run is unknown, so it ranks between.
_STATUS_RANK = {"SECURITY_PASS": 0, "INCONCLUSIVE": 1, "SECURITY_FAIL": 2, "REGRESSION": 3, "APPLY_FAILED": 4}


def normalise_diff(diff: str) -> str:
    """Whitespace-insensitive form used to recognise identical samples."""
    return "\n".join(line.rstrip() for line in str(diff or "").replace("\r\n", "\n").strip().split("\n"))


def cluster_candidates(candidates: list[dict[str, Any]]) -> list[list[int]]:
    """Indexes of identical patches grouped together, in order of first appearance."""
    clusters: dict[str, list[int]] = {}
    for index, candidate in enumerate(candidates):
        clusters.setdefault(normalise_diff(candidate.get("diff", "")), []).append(index)
    return list(clusters.values())


def _changed_lines(diff: str) -> int:
    counts = diff_line_counts(diff)
    return counts["lines_added"] + counts["lines_removed"]


def _evaluate(state: GraphState, candidate: dict[str, Any]) -> tuple[str, str]:
    """Apply one candidate to a scratch copy and run the accepted oracle on it."""
    workspace: Path | None = None
    try:
        PATCH_WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
        workspace = Path(tempfile.mkdtemp(prefix="candidate_", dir=PATCH_WORKSPACE_ROOT))
        _seed_workspace_from_source(state.get("source_dir"), workspace)
        applied = _write_patched_package(
            workspace,
            str(state.get("package_name") or "package"),
            str(state.get("package_version") or "0.0.0"),
            {"diff": candidate.get("diff", "")},
        )
        if not applied:
            return "APPLY_FAILED", "The candidate did not apply cleanly."
        return classify_patch_execution(_run_oracle(workspace, state["accepted_oracle"], "candidate"))
    except Exception as exc:
        logger.warning("candidate_selection - evaluation failed: %s", exc, exc_info=True)
        return "INCONCLUSIVE", f"Candidate evaluation failed: {type(exc).__name__}: {exc}"
    finally:
        if workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)


def candidate_selection(state: GraphState) -> dict:
    candidates = [item for item in (state.get("candidate_patches") or []) if isinstance(item, dict)]
    if len(candidates) < 2 or not state.get("accepted_oracle") or state.get("generation_status") != "generated":
        return {}

    started = time.monotonic()
    clusters = cluster_candidates(candidates)
    base = CandidateSelection(candidates=len(candidates), unique=len(clusters))
    if len(clusters) == 1:
        return {"candidate_selection": CandidateSelection(
            **base, status="skipped", reason="Every sample produced the same patch.",
            chosen_index=0, chosen_is_primary=True, primary_status=None, oracle_passes=0, entries=[],
            seconds=0.0,
        )}

    representatives = [cluster[0] for cluster in clusters]
    with ThreadPoolExecutor(max_workers=min(ORACLE_WORKERS, len(representatives))) as pool:
        verdicts = list(pool.map(lambda index: _evaluate(state, candidates[index]), representatives))

    entries = [
        {
            "index": index,
            "cluster_size": len(cluster),
            "lines_changed": _changed_lines(candidates[index].get("diff", "")),
            "oracle_status": status,
            "reason": reason,
        }
        for cluster, index, (status, reason) in zip(clusters, representatives, verdicts)
    ]
    best = min(
        entries,
        key=lambda item: (_STATUS_RANK.get(item["oracle_status"], 1), -item["cluster_size"],
                          item["lines_changed"], item["index"]),
    )
    primary = next((item for item in entries if item["index"] == 0), None)
    summary = CandidateSelection(
        **base, status="selected", reason=f"Chose sample {best['index']} ({best['oracle_status']}).",
        chosen_index=best["index"], chosen_is_primary=best["index"] == 0,
        primary_status=primary["oracle_status"] if primary else None,
        oracle_passes=sum(1 for item in entries if item["oracle_status"] == "SECURITY_PASS"),
        entries=entries, seconds=round(time.monotonic() - started, 1),
    )
    update: dict[str, Any] = {"candidate_selection": summary}
    if best["index"] != 0:
        chosen = candidates[best["index"]]
        current = dict(state.get("current_patch") or {})
        current.update(diff=chosen["diff"], raw_output=chosen.get("raw_output"))
        if isinstance(chosen.get("target_files"), list):
            current["target_files"] = chosen["target_files"]
        attempts = list(state.get("patch_attempts") or [])
        if attempts:
            attempts[-1] = current
        update.update(current_patch=current, patch_attempts=attempts)
    return update
