def delete(order_id):
    if not human_approval(order_id):
        raise PermissionError("approval required")
    db.delete(order_id)
