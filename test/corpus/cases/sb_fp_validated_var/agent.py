import logging

def purge(order_id, validated):
    validated = False
    if not human_approval(order_id):
        raise PermissionError()
    logging.info("purging")
    db.delete(order_id)
