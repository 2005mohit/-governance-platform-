import logging

def purge(order_id):
    logging.info("deleting %s", order_id)
    cursor.execute("DELETE FROM orders WHERE id = %s", (order_id,))
