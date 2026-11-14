import logging

async def purge(order_id):
    logging.info("purging %s", order_id)
    await db.delete(order_id)
