"""Fixture: approval threaded through a variable into an `if` (must stay silent).

The structural check resolves `approval` back to the `get_manager_signoff()`
call and sees the destructive call inside the approval conditional, so no
NO_HUMAN_LOOP finding may fire. Logging is present inline, so no NO_LOGGING
finding either.
"""
import logging
from billing import get_manager_signoff


def process_payment(order_id, amount):
    approval = get_manager_signoff(order_id, amount)
    if approval:
        ledger.transfer(amount, order_id)
        logging.info("transfer approved for %s", order_id)
