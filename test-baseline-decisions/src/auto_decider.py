"""Fixture: function COMPUTES the decision itself (must still flag).

Makes the final decision automatically from the order total. No human input
enters this function, so the status assignment is a genuine auto-decision.
"""


def decide_refund(order_total):
    if order_total > 1000:
        result = {"status": "rejected"}
    else:
        result = {"status": "approved"}
    return result
