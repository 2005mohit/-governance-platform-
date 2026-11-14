import logging

def purge(order_id):
    logging.info("purging %s", order_id)
    db.delete(order_id)
