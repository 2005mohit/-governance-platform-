import logging

def delete(o):
    if not human_approval(o):
        return
    logging.info("deleting")
    db.delete(o)
