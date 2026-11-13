# Synthetic fixture: raw exception text is returned to the client. The
# scanner should report ERROR_LEAKAGE.
from fastapi import HTTPException


def read_record(store, record_id):
    try:
        return store[record_id]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
