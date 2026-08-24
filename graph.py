from langgraph.graph import StateGraph, MessagesState, START, END
from package_input import package_input
from vulnerability_detection import vulnerability_detection
from patch_generation import patch_generation
from patch_application import patch_application
from patch_validation import patch_validation
from outcome_classification import outcome_classification


graph = StateGraph(MessagesState)
graph.add_node('package_input_node', package_input)
graph.add_node('vulnerability_detection_node', vulnerability_detection)
graph.add_node('patch_generation_node', patch_generation)
graph.add_node('patch_application_node', patch_application)
graph.add_node('patch_validation_node', patch_validation)
graph.add_node('outcome_classification_node', outcome_classification)

graph.add_edge(START, "package_input_node")
graph.add_edge("package_input_node", 'vulnerability_detection_node')
graph.add_edge("vulnerability_detection_node", 'patch_generation_node')
graph.add_edge("patch_generation_node", 'patch_application_node')
graph.add_edge("patch_application_node", 'patch_validation_node')
graph.add_edge("patch_validation_node", 'outcome_classification_node')
graph.add_edge('outcome_classification_node', END)
graph = graph.compile()
