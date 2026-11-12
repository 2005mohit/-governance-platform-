"""Fixture: the ONLY unsafe-deserialization occurrences here are commented out.

Comment-aware evidence must skip them, yielding zero findings — not a
wrong-line finding pointing at a comment.
"""
# Retired model loader, kept for reference:
# torch.load(legacy_model_path, map_location="cpu")
# pickle.load(open("legacy.pkl", "rb"))

CURRENT_MODEL = "models/production_v3.pt"
