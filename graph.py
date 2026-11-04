from langgraph.graph import StateGraph, START, END
from package_input import package_input
from vulnerability_detection import vulnerability_detection
from og_patch_resolution import og_patch_resolution
from patch_generation import patch_generation
from patch_application import patch_application
from vulnerability_rescan import vulnerability_rescan
from patch_validation import patch_validation
from adversarial_evaluation import adversarial_evaluation
from patch_scoring import patch_scoring
from maintainer_eval import maintainer_eval
from oracle_generation import oracle_generation
from oracle_validation import oracle_validation, generated_patch_oracle_validation
from vulnerability_localization import vulnerability_localization
from state import GraphState


def route_after_patch_generation(state: GraphState) -> str:
    """Do not run Docker for a missing/invalid model response.

    Generation failures still flow to validation for classification.
    """
    if state.get("generation_status") == "failed" or not state.get("current_patch"):
        return "validation"
    return "application"


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

    if state.get("retry_count", 0) >= state.get("max_retries", 1):
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
graph.add_node("vulnerability_localization_node", vulnerability_localization)
graph.add_node("oracle_generation_node", oracle_generation)
graph.add_node("oracle_validation_node", oracle_validation)
graph.add_node("patch_generation_node", patch_generation)
graph.add_node("patch_application_node", patch_application)
graph.add_node("vulnerability_rescan_node", vulnerability_rescan)
graph.add_node("patch_validation_node", patch_validation)
graph.add_node("adversarial_evaluation_node", adversarial_evaluation)
graph.add_node("generated_patch_oracle_validation_node", generated_patch_oracle_validation)
graph.add_node("patch_scoring_node", patch_scoring)
graph.add_node("maintainer_eval_node", maintainer_eval)
graph.add_node("increment_retry", increment_retry)

graph.add_edge(START, "package_input_node")
graph.add_edge("package_input_node", "vulnerability_detection_node")
graph.add_edge("vulnerability_detection_node", "og_patch_resolution_node")
graph.add_edge("og_patch_resolution_node", "vulnerability_localization_node")
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
        "application": "patch_application_node",
        "validation": "patch_validation_node",
    },
)
graph.add_edge("patch_application_node", "vulnerability_rescan_node")
graph.add_edge("vulnerability_rescan_node", "generated_patch_oracle_validation_node")
graph.add_edge("generated_patch_oracle_validation_node", "adversarial_evaluation_node")
graph.add_edge("adversarial_evaluation_node", "patch_validation_node")
graph.add_edge("patch_validation_node", "patch_scoring_node")
graph.add_conditional_edges(
    "patch_scoring_node",
    route_after_classification,
    {
        "retry": "increment_retry",
        "eval": "maintainer_eval_node",
    },
)
graph.add_edge("increment_retry", "patch_generation_node")
graph.add_edge("maintainer_eval_node", END)

graph = graph.compile()

