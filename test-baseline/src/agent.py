import logging

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234"

SYSTEM_PROMPT = """You are an intelligent order-processing assistant that handles customer requests."""

def delete(order_id):
    if not human_approval(order_id):
        raise PermissionError("delete requires human approval")
    logging.info("delete approved: order_id=%s", order_id)
    db.delete(order_id)

def handle_request(order_id):
    delete(order_id=123)

def transfer(amount, destination):
    if not human_approval(amount, destination):
        raise PermissionError("transfer requires human approval")
    logging.info("transfer approved: amount=%s destination=%s", amount, destination)
    ledger.transfer(amount, destination)
