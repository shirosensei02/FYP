from langgraph.graph import StateGraph, START, END
from package_input import package_input
from vulnerability_detection import vulnerability_detection
from og_patch_resolution import og_patch_resolution
from patch_generation import patch_generation
from patch_application import apply_patch, package_validation
from vulnerability_rescan import vulnerability_rescan
from patch_validation import patch_validation, record_locked_oracle_failure, skip_package_tests
from adversarial_evaluation import adversarial_evaluation
from patch_scoring import patch_scoring
from maintainer_eval import maintainer_eval
from repo_graph import repo_graph_node, route_after_repo_graph
from locator import locator_node, route_after_locator
from oracle_generation import oracle_generation
from oracle_validation import oracle_validation, generated_patch_oracle_validation
from vulnerability_localization import vulnerability_localization
from final_evaluation import final_evaluation
from state import GraphState


def route_after_patch_generation(state: GraphState) -> str:
    """Fetch from the package graph, skip Docker for an invalid response, or apply.

    Generation failures still flow to validation for classification.
    """
    if state.get("graph_request"):
        return "repo_graph"
    if state.get("generation_status") == "failed" or not state.get("current_patch"):
        return "validation"
    return "application"


def route_after_apply(state: GraphState) -> str:
    """A patch that did not land cannot be oracle-tested."""
    if state.get("patch_applied") is True:
        return "oracle"
    return "validation"


def _writer_attempts_remain(state: GraphState) -> bool:
    maximum = state.get("max_retries")
    limit = 5 if maximum is None else int(maximum)
    return int(state.get("retry_count") or 0) < limit


def route_after_generated_oracle(state: GraphState) -> str:
    """Package tests run only after the locked oracle passes, or when it cannot judge the patch.

    An exploit that still succeeds, or an ordinary call that fails, goes back to
    the writer with the oracle output. A crash, timeout, or missing result is
    not a source defect, so the package tests still run and the writer is not
    retried for the oracle itself.
    """
    status = (state.get("generated_patch_oracle_validation") or {}).get("status")
    if status in {"SECURITY_FAIL", "REGRESSION"}:
        return "retry" if _writer_attempts_remain(state) else "terminal"
    return "package_tests"


def route_after_oracle_validation(state: GraphState) -> str:
    """Correct an invalid oracle within its independent attempt budget."""
    validation = state.get("oracle_validation") or {}
    attempts = int(state.get("oracle_attempt_count") or 0)
    maximum = int(state.get("max_oracle_attempts") or 5)
    if validation.get("status") == "INVALID" and attempts < maximum:
        return "retry"
    return "continue"


def route_after_classification(state: GraphState) -> str:
    """Retry a failed patch. Infrastructure failures and finished attempts go to evaluation."""
    if (state.get("validation") or {}).get("failure_stage") in {"setup", "dependencies"}:
        return "eval"

    # Retrying can only help source defects. An unavailable/inconclusive
    # security oracle is independent of the generated patch.
    if state.get("classification") in {"pass", "inconclusive", "pass_unverified"}:
        return "eval"

    if not _writer_attempts_remain(state):
        return "eval"

    return "retry"


def increment_retry(state: GraphState) -> dict:
    return {
        "retry_count": state.get("retry_count", 0) + 1,
        # A new patch attempt must never inherit the previous patch's verdict.
        "generated_patch_oracle_validation": None,
    }


graph = StateGraph(GraphState)
graph.add_node("package_input_node", package_input)
graph.add_node("vulnerability_detection_node", vulnerability_detection)
graph.add_node("og_patch_resolution_node", og_patch_resolution)
graph.add_node("repo_graph_node", repo_graph_node)
graph.add_node("locator_node", locator_node)
graph.add_node("vulnerability_localization_node", vulnerability_localization)
graph.add_node("oracle_generation_node", oracle_generation)
graph.add_node("oracle_validation_node", oracle_validation)
graph.add_node("patch_generation_node", patch_generation)
graph.add_node("apply_patch_node", apply_patch)
graph.add_node("package_validation_node", package_validation)
graph.add_node("vulnerability_rescan_node", vulnerability_rescan)
graph.add_node("patch_validation_node", patch_validation)
graph.add_node("adversarial_evaluation_node", adversarial_evaluation)
graph.add_node("generated_patch_oracle_validation_node", generated_patch_oracle_validation)
graph.add_node("record_locked_oracle_failure_node", record_locked_oracle_failure)
graph.add_node("skip_package_tests_node", skip_package_tests)
graph.add_node("patch_scoring_node", patch_scoring)
graph.add_node("final_evaluation_node", final_evaluation)
graph.add_node("maintainer_eval_node", maintainer_eval)
graph.add_node("increment_retry", increment_retry)

graph.add_edge(START, "package_input_node")
graph.add_edge("package_input_node", "vulnerability_detection_node")
graph.add_edge("vulnerability_detection_node", "og_patch_resolution_node")
graph.add_edge("og_patch_resolution_node", "repo_graph_node")
graph.add_conditional_edges(
    "repo_graph_node",
    route_after_repo_graph,
    {
        "locator": "locator_node",
        "generation": "patch_generation_node",
    },
)
graph.add_conditional_edges(
    "locator_node",
    route_after_locator,
    {
        "repo_graph": "repo_graph_node",
        "locator": "locator_node",
        "generation": "vulnerability_localization_node",
    },
)
graph.add_edge("vulnerability_localization_node", "oracle_generation_node")
graph.add_edge("oracle_generation_node", "oracle_validation_node")
graph.add_conditional_edges(
    "oracle_validation_node",
    route_after_oracle_validation,
    {
        "retry": "oracle_generation_node",
        "continue": "patch_generation_node",
    },
)
graph.add_conditional_edges(
    "patch_generation_node",
    route_after_patch_generation,
    {
        "repo_graph": "repo_graph_node",
        "application": "apply_patch_node",
        "validation": "patch_validation_node",
    },
)
graph.add_conditional_edges(
    "apply_patch_node",
    route_after_apply,
    {
        "oracle": "generated_patch_oracle_validation_node",
        "validation": "patch_validation_node",
    },
)
graph.add_conditional_edges(
    "generated_patch_oracle_validation_node",
    route_after_generated_oracle,
    {
        "retry": "record_locked_oracle_failure_node",
        "package_tests": "package_validation_node",
        "terminal": "skip_package_tests_node",
    },
)
graph.add_edge("record_locked_oracle_failure_node", "increment_retry")
graph.add_edge("skip_package_tests_node", "vulnerability_rescan_node")
graph.add_edge("package_validation_node", "vulnerability_rescan_node")
graph.add_edge("vulnerability_rescan_node", "adversarial_evaluation_node")
graph.add_edge("adversarial_evaluation_node", "patch_validation_node")
graph.add_edge("patch_validation_node", "patch_scoring_node")
graph.add_conditional_edges(
    "patch_scoring_node",
    route_after_classification,
    {
        "retry": "increment_retry",
        "eval": "final_evaluation_node",
    },
)
graph.add_edge("increment_retry", "patch_generation_node")
graph.add_edge("final_evaluation_node", "maintainer_eval_node")
graph.add_edge("maintainer_eval_node", END)

graph = graph.compile()
