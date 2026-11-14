import logging

def delete(o):
    assert human_approval(o)
    logging.info("deleting")
    db.delete(o)
