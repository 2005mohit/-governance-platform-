import logging

def delete(o):
    if not human_approval(o):
        raise PermissionError()
    logging.info("deleting")
    db.delete(o)
