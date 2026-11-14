from fastapi import FastAPI, Depends
app = FastAPI()

@app.get("/orders")
def list_orders(user=Depends(get_current_user)):
    return {"orders": []}
