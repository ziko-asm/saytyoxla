"""Vercel entry point: every request is routed here (see vercel.json) and served by the FastAPI app."""
from web.app import app  # noqa: F401
