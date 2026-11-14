from agents import function_tool

@function_tool
def remove(q):
    logger.info("removing")
    db.delete(q)
