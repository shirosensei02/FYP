from langgraph.graph import StateGraph, MessagesState, START, END
from package_input import package_input

def mock_llm(state: MessagesState):
    return {"messages": [{"role": "ai", "content": "hello world"}]}



graph = StateGraph(MessagesState)
graph.add_node(mock_llm)
graph.add_node('package_input_node', package_input)

graph.add_edge(START, "mock_llm")
graph.add_edge("mock_llm", 'package_input_node')
graph.add_edge('package_input_node', END)
graph = graph.compile()

graph.invoke({"messages": [{"role": "user", "content": "hi!"}]})