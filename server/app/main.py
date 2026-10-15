"""Main FastAPI application for SecureChat."""

from fastapi import FastAPI

app = FastAPI(title="SecureChat Server")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
