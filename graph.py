from langgraph.graph import StateGraph, START, END
from package_input import package_input
from vulnerability_detection import vulnerability_detection
from og_patch_resolution import og_patch_resolution
from patch_generation import patch_generation
from patch_application import patch_application
from vulnerability_rescan import vulnerability_rescan
from patch_validation import patch_validation
from patch_scoring import patch_scoring
from state import GraphState


def route_after_patch_generation(state: GraphState) -> str:
    """Do not run Docker for a missing/invalid model response.

    Generation failures still flow to validation for classification.
    """
    if state.get("generation_status") == "failed" or not state.get("current_patch"):
        return "validation"
    return "application"


def route_after_classification(state: GraphState) -> str:
    if state.get("classification") == "pass":
        return "end"

    if state.get("retry_count") >= state.get("max_retries"):
        return "end"

    return "retry"


def increment_retry(state: GraphState) -> dict:
    return {"retry_count": state.get("retry_count", 0) + 1}


graph = StateGraph(GraphState)
graph.add_node("package_input_node", package_input)
graph.add_node("vulnerability_detection_node", vulnerability_detection)
graph.add_node("og_patch_resolution_node", og_patch_resolution)
graph.add_node("patch_generation_node", patch_generation)
graph.add_node("patch_application_node", patch_application)
graph.add_node("vulnerability_rescan_node", vulnerability_rescan)
graph.add_node("patch_validation_node", patch_validation)
graph.add_node("patch_scoring_node", patch_scoring)
graph.add_node("increment_retry", increment_retry)

graph.add_edge(START, "package_input_node")
graph.add_edge("package_input_node", "vulnerability_detection_node")
graph.add_edge("vulnerability_detection_node", "og_patch_resolution_node")
graph.add_edge("og_patch_resolution_node", "patch_generation_node")
graph.add_conditional_edges(
    "patch_generation_node",
    route_after_patch_generation,
    {
        "application": "patch_application_node",
        "validation": "patch_validation_node",
    },
)
graph.add_edge("patch_application_node", "vulnerability_rescan_node")
graph.add_edge("vulnerability_rescan_node", "patch_validation_node")
graph.add_edge("patch_validation_node", "patch_scoring_node")
graph.add_conditional_edges(
    "patch_scoring_node",
    route_after_classification,
    {
        "retry": "increment_retry",
        "end": END,
    },
)
graph.add_edge("increment_retry", "patch_generation_node")

graph = graph.compile()
