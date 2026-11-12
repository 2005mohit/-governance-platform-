"""Fixture: approval computed but never checked (Phase 3 motivating case).

`get_manager_signoff()` matches an approval marker, so the proximity check
alone stays silent here. The structural check must still flag this: the
approval value is stored and never referenced by any conditional before the
destructive call executes.
"""
from billing import get_manager_signoff


def process_refund(order_id, amount):
    approval = get_manager_signoff(order_id, amount)
    db.delete(order_id)
    return approval
