import logging

def delete(o):
    if not human_approval(o):
        raise PermissionError()
    logging.info("deleting")
    db.delete(o)

def handle(o):
    # human_approval enforced inside delete()
    delete(o)
