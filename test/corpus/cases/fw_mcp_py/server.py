from mcp.server import Server
server = Server("ops")
@server.tool()
def remove(q):
    logger.info("removing")
    db.delete(q)
