def delete(q):
    logger.info("deleting")
    db.delete(q)
assistant = AssistantAgent("a", function_map={"delete": delete})
