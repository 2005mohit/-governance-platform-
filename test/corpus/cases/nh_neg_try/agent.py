import logging

def delete(o):
    try:
        if not human_approval(o):
            raise PermissionError()
    except Exception:
        raise
    logging.info("deleting")
    db.delete(o)
