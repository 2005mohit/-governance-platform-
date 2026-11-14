import logging

def purge(order_id):
    logging.info("deleting %s", order_id)
    getattr(db, "delete")(order_id)
