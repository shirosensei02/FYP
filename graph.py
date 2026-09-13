from langgraph.graph import StateGraph, MessagesState, START, END
from package_input import package_input
from vulnerability_detection import vulnerability_detection
from patch_generation import patch_generation
from patch_application import patch_application
from patch_validation import patch_validation
from state import GraphState

def route_after_patch_generation(state: GraphState) -> str:
    """Do not run Docker for a missing/invalid model response.

    Generation failures still flow to validation for classification, but are
    not persisted because only successful patches are stored.
    """
    if state.get("generation_status") == "failed" or not state.get("current_patch"):
        return "validation"
    return "application"

graph = StateGraph(GraphState)
graph.add_node('package_input_node', package_input)
graph.add_node('vulnerability_detection_node', vulnerability_detection)
graph.add_node('patch_generation_node', patch_generation)
graph.add_node('patch_application_node', patch_application)
graph.add_node('patch_validation_node', patch_validation)

graph.add_edge(START, "package_input_node")
graph.add_edge("package_input_node", 'vulnerability_detection_node')
graph.add_edge("vulnerability_detection_node", 'patch_generation_node')
graph.add_conditional_edges(
    "patch_generation_node",
    route_after_patch_generation,
    {"application": "patch_application_node", "validation": "patch_validation_node"},
)
graph.add_edge("patch_application_node", 'patch_validation_node')

graph.add_edge("patch_validation_node", END)

graph = graph.compile()
