# Synthetic fixture for exit-code tests: one MEDIUM finding (CORS_WILDCARD).
from fastapi.middleware.cors import CORSMiddleware


def add_cors(app):
    app.add_middleware(CORSMiddleware, allow_origins=["*"])
