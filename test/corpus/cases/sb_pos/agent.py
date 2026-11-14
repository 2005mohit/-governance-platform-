import logging

def purge(order_id, skip_validation):
    skip_validation = True
    if not human_approval(order_id):
        raise PermissionError()
    logging.info("purging")
    db.delete(order_id)
