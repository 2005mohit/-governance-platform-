# Synthetic fixture: permissive CORS. The scanner should report
# CORS_WILDCARD.
from fastapi.middleware.cors import CORSMiddleware


def add_cors(app):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
    )
