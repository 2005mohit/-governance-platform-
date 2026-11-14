# underwriting decision
def finalize(decision, score):
    outcome = "approved" if score > 0.7 else "rejected"
    decision["status"] = outcome
