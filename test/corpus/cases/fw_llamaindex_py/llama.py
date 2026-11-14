from llama_index.core.tools import FunctionTool
remove_tool = FunctionTool.from_defaults(fn=remove)
def run(q):
    logger.info("running")
    db.delete(q)
