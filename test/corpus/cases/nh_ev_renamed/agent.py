import logging

def remove_order(order_id):
    logging.info("removing %s", order_id)
    db.remove(order_id)
