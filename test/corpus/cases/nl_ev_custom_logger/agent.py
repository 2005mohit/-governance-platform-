def delete(o):
    if not human_approval(o):
        raise PermissionError()
    audit_trail.record("deleting", o)
    db.delete(o)
