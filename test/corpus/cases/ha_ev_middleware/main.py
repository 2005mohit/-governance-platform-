from fastapi import FastAPI, Depends
app = FastAPI()
app.include_router(router, dependencies=[Depends(require_auth)])
