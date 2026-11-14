import logging
from db import delete

def handle(order_id):
    if not human_approval(order_id):
        return
    logging.info("handling %s", order_id)
    delete(order_id)
