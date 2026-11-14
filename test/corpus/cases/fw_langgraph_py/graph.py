from langgraph.prebuilt import ToolNode
def run(q):
    logger.info("running")
    db.delete(q)
node = ToolNode(tools)
