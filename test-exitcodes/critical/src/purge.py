# Synthetic fixture for exit-code tests: a CRITICAL finding
# (NO_HUMAN_LOOP) plus a HIGH one (NO_LOGGING).
def purge_orders(db, order):
    db.delete(order)
