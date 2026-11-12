"""Fixture: handler RECORDS a human decision (must stay silent).

`decision` arrives as a parameter and the status assignments sit in branches
conditioned on it. The function persists a decision made elsewhere; it does
not compute one. FIX 1 must suppress both assignments below.
"""


def record_review_decision(decision, order_id):
    if decision == "approved":
        store.update(order_id, {"status": "approved"})
    else:
        store.update(order_id, {"status": "rejected"})
