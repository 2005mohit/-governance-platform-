from fastapi import HTTPException
def fail(e):
    raise HTTPException(status_code=500, detail=str(e))
