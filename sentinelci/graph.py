from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from state import ScanState
from agents.fetcher import fetcher_node
from agents.scanner import scanner_node
from agents.cve_matcher import cve_matcher_node
from agents.ai_reasoner import ai_reasoner_node
from agents.hitl import hitl_node
from agents.reporter import reporter_node
from config import AUTO_BLOCK_THRESHOLD


def should_run_hitl(state: ScanState) -> str:
    score = state.get("security_score", 0)
    if score >= AUTO_BLOCK_THRESHOLD:
        return "hitl"
    elif state.get("hitl_required"):
        return "hitl"
    else:
        return "reporter"


def build_graph():
    checkpointer = MemorySaver()
    graph = StateGraph(ScanState)

    graph.add_node("fetcher", fetcher_node)
    graph.add_node("scanner", scanner_node)
    graph.add_node("cve_matcher", cve_matcher_node)
    graph.add_node("ai_reasoner", ai_reasoner_node)
    graph.add_node("hitl", hitl_node)
    graph.add_node("reporter", reporter_node)

    graph.set_entry_point("fetcher")
    graph.add_edge("fetcher", "scanner")
    graph.add_edge("scanner", "cve_matcher")
    graph.add_edge("cve_matcher", "ai_reasoner")

    graph.add_conditional_edges(
        "ai_reasoner",
        should_run_hitl,
        {
            "hitl": "hitl",
            "reporter": "reporter"
        }
    )

    graph.add_edge("hitl", "reporter")
    graph.add_edge("reporter", END)

    return graph.compile(checkpointer=checkpointer, interrupt_before=["hitl"])


app_graph = build_graph()