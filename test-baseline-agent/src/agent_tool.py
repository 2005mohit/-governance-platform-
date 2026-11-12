"""Fixture: the same unguarded-delete pattern, but registered as a LangChain tool.

Unlike test-baseline/src/agent.py (no framework registration), this file
carries a real `@tool` decorator, so its NO_HUMAN_LOOP / NO_LOGGING findings
must keep the agent-oversight claim ("agent-tool" exposure) rather than being
relabeled as general code risk.
"""
from langchain.tools import tool


@tool
def delete(order_id: str) -> str:
    """Delete an order by its ID."""
    db.delete(order_id)
    return f"deleted {order_id}"
