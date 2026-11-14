# underwriting decision service
def finalize(application, score):
    decision = {}
    decision["status"] = "approved" if score > 0.7 else "rejected"
    return decision
