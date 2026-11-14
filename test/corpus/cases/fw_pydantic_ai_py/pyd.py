from pydantic_ai import Agent
agent = Agent("openai:gpt-4o")
@agent.tool
def remove(q):
    logger.info("removing")
    db.delete(q)
