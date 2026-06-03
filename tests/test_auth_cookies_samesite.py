import os
import sys
import types
import asyncio
import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock

def _ensure_stub(name: str, **attrs):
    if "." in name:
        parent_name, _, child_name = name.rpartition(".")
        if parent_name not in sys.modules:
            parent = types.ModuleType(parent_name)
            real_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                *parent_name.split("."),
            )
            parent.__path__ = [real_path] if os.path.isdir(real_path) else []
            sys.modules[parent_name] = parent
        else:
            parent = sys.modules[parent_name]
    else:
        parent = None
        child_name = None

    mod = sys.modules.get(name)
    if mod is None:
        mod = types.ModuleType(name)
        sys.modules[name] = mod
    for k, v in attrs.items():
        if not hasattr(mod, k):
            setattr(mod, k, v)
    if parent is not None and not hasattr(parent, child_name):
        setattr(parent, child_name, mod)
    return mod

@pytest.fixture(autouse=True)
def _event_loop_stubs(monkeypatch):
    db = _ensure_stub("core.database", SessionLocal=MagicMock())
    auth = _ensure_stub("core.auth", AuthManager=MagicMock())
    monkeypatch.setitem(sys.modules, "core.database", db)
    monkeypatch.setitem(sys.modules, "core.auth", auth)

from routes.auth_routes import setup_auth_routes, LoginRequest

def _login_endpoint(auth_manager):
    router = setup_auth_routes(auth_manager)
    for r in router.routes:
        if getattr(r, "path", None) == "/api/auth/login" and "POST" in getattr(r, "methods", set()):
            return r.endpoint
    raise AssertionError("login route not found")

def _logout_endpoint(auth_manager):
    router = setup_auth_routes(auth_manager)
    for r in router.routes:
        if getattr(r, "path", None) == "/api/auth/logout" and "POST" in getattr(r, "methods", set()):
            return r.endpoint
    raise AssertionError("logout route not found")

def test_login_sets_samesite_none_secure_true_in_hf_space(monkeypatch):
    monkeypatch.setenv("SPACE_ID", "ChiefJaydeep919/odysseus")
    auth = MagicMock()
    auth.verify_password.return_value = True
    auth.totp_enabled.return_value = False
    auth.create_session.return_value = "tok-123"
    login = _login_endpoint(auth)
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), cookies={})
    response = MagicMock()
    body = LoginRequest(username="alice", password="password123", remember=True)
    result = asyncio.run(login(body=body, request=request, response=response))
    assert result["ok"] is True
    response.set_cookie.assert_called_once()
    kwargs = response.set_cookie.call_args[1]
    assert kwargs["samesite"] == "none"
    assert kwargs["secure"] is True

def test_login_defaults_to_samesite_lax(monkeypatch):
    monkeypatch.delenv("SPACE_ID", raising=False)
    monkeypatch.delenv("ALLOW_FRAMING", raising=False)
    monkeypatch.setenv("SECURE_COOKIES", "false")
    auth = MagicMock()
    auth.verify_password.return_value = True
    auth.totp_enabled.return_value = False
    auth.create_session.return_value = "tok-123"
    login = _login_endpoint(auth)
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), cookies={})
    response = MagicMock()
    body = LoginRequest(username="alice", password="password123", remember=True)
    result = asyncio.run(login(body=body, request=request, response=response))
    assert result["ok"] is True
    response.set_cookie.assert_called_once()
    kwargs = response.set_cookie.call_args[1]
    assert kwargs["samesite"] == "lax"
    assert kwargs["secure"] is False

def test_logout_deletes_cookie_correctly(monkeypatch):
    monkeypatch.setenv("SPACE_ID", "ChiefJaydeep919/odysseus")
    auth = MagicMock()
    logout = _logout_endpoint(auth)
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), cookies={"odysseus_session": "tok-123"})
    response = MagicMock()
    result = asyncio.run(logout(request=request, response=response))
    assert result["ok"] is True
    response.delete_cookie.assert_called_once()
    kwargs = response.delete_cookie.call_args[1]
    assert kwargs["samesite"] == "none"
    assert kwargs["secure"] is True
