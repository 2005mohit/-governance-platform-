import logging

def purge(order_id):
    approved = human_approval(order_id)
    logging.info("approved=%s", approved)
    db.delete(order_id)
