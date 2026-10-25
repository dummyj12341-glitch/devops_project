"""Load the app under test (TARGET_APP=app | app_secure) by file path."""
import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TARGET = os.environ.get("TARGET_APP", "app")


@pytest.fixture(scope="session")
def client():
    app_dir = ROOT / TARGET
    sys.path.insert(0, str(app_dir))
    spec = importlib.util.spec_from_file_location("server", app_dir / "server.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["server"] = module
    spec.loader.exec_module(module)
    module.app.config["TESTING"] = True
    # the secure app enforces CSRF tokens; unit tests call the endpoints directly
    module.app.config["WTF_CSRF_ENABLED"] = False
    with module.app.test_client() as c:
        yield c
