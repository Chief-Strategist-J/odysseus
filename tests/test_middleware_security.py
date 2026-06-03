import os
import sys
import types
from unittest.mock import AsyncMock, MagicMock
import pytest

if "core.database" not in sys.modules:
    _core_db = types.ModuleType("core.database")
    for _name in [
        "SessionLocal", "ModelEndpoint", "Session", "ChatMessage", "Document",
        "DocumentVersion", "GalleryImage", "GalleryAlbum", "Note",
        "CalendarCal", "CalendarEvent", "ScheduledTask", "TaskRun",
        "McpServer",
    ]:
        setattr(_core_db, _name, MagicMock())
    sys.modules["core.database"] = _core_db

from fastapi import Request
from starlette.responses import Response
from core.middleware import SecurityHeadersMiddleware

@pytest.mark.asyncio
async def test_middleware_security_headers_default(monkeypatch):
    monkeypatch.delenv("SPACE_ID", raising=False)
    monkeypatch.delenv("ALLOW_FRAMING", raising=False)
    
    middleware = SecurityHeadersMiddleware(MagicMock())
    request = MagicMock(spec=Request)
    request.state = MagicMock()
    request.url = MagicMock()
    request.url.path = "/"
    
    async def call_next(req):
        return Response(content=b"OK")
        
    response = await middleware.dispatch(request, call_next)
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]

@pytest.mark.asyncio
async def test_middleware_security_headers_hf_space(monkeypatch):
    monkeypatch.setenv("SPACE_ID", "test/space")
    
    middleware = SecurityHeadersMiddleware(MagicMock())
    request = MagicMock(spec=Request)
    request.state = MagicMock()
    request.url = MagicMock()
    request.url.path = "/"
    
    async def call_next(req):
        return Response(content=b"OK")
        
    response = await middleware.dispatch(request, call_next)
    assert "X-Frame-Options" not in response.headers
    assert "frame-ancestors 'self' https://huggingface.co https://*.hf.space" in response.headers["Content-Security-Policy"]

@pytest.mark.asyncio
async def test_middleware_security_headers_allow_framing(monkeypatch):
    monkeypatch.delenv("SPACE_ID", raising=False)
    monkeypatch.setenv("ALLOW_FRAMING", "true")
    
    middleware = SecurityHeadersMiddleware(MagicMock())
    request = MagicMock(spec=Request)
    request.state = MagicMock()
    request.url = MagicMock()
    request.url.path = "/"
    
    async def call_next(req):
        return Response(content=b"OK")
        
    response = await middleware.dispatch(request, call_next)
    assert "X-Frame-Options" not in response.headers
    assert "frame-ancestors 'self' https://huggingface.co https://*.hf.space" in response.headers["Content-Security-Policy"]
