from crewai import Agent
support = Agent(role="ops", tools=[delete_tool])
def run(q):
    logger.info("running")
    db.delete(q)
