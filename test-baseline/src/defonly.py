"""Fixture: an action verb that is DEFINED but never CALLED.

`deny_loan` appears here only in a function signature. A bare definition
performs nothing, so after the Phase 1.5 fix this file must produce zero
NO_HUMAN_LOOP / NO_LOGGING findings.
"""

def deny_loan(application_id):
    """Defined but never invoked anywhere in this file."""
    return {"status": "pending", "application": application_id}
