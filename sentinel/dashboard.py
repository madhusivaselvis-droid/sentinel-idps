"""
dashboard.py
FastAPI backend exposing session/event/integrity data for the dashboard,
and serving the static frontend (polling-based - simple and reliable).
"""

import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import storage
import verify_integrity
import sentinel_api

# Resolve the static directory relative to this file so the dashboard
# works regardless of the process working directory.
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = FastAPI(title="ChimeraMesh Dashboard API")

# No CORS middleware: the dashboard's own JS only calls same-origin
# /api/... paths served by this same FastAPI app, so cross-origin access
# is never actually needed. If a separate frontend host is added later,
# whitelist its exact origin explicitly - never use allow_origins=["*"]
# on a security-monitoring API.


@app.get("/api/summary")
def summary():
    return storage.get_summary()


@app.get("/api/sessions")
def sessions():
    return storage.get_sessions()


@app.get("/api/events")
def events(limit: int = 50):
    return storage.get_recent_events(limit)


@app.get("/api/integrity")
def integrity():
    ok = verify_integrity.verify()
    return {"intact": ok}


app.include_router(sentinel_api.router, prefix="/api/sentinel")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


if __name__ == "__main__":
    import uvicorn
    storage.init_db()
    uvicorn.run(app, host="0.0.0.0", port=9000)
