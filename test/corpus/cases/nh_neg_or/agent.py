import logging

def delete(o):
    if not human_approval(o) or not is_valid(o):
        raise PermissionError()
    logging.info("deleting")
    db.delete(o)
