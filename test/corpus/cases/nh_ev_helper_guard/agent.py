import logging

def delete(order_id):
    if not human_approval(order_id):
        raise PermissionError("approval required")
    logging.info("deleting %s", order_id)
    db.delete(order_id)

def handle(order_id):
    logging.info("handling %s", order_id)
    delete(order_id)
