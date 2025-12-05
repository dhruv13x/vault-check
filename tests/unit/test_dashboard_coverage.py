
import pytest
from unittest.mock import MagicMock
from vault_check.dashboard import create_dashboard_app

def test_create_dashboard_app():
    # Just calling it should execute the definition of routes
    app = create_dashboard_app("reports_dir")
    assert app is not None
    # Verify routes are added
    # We can inspect app.router.routes() if we really want, but coverage is the goal
    assert len(app.router.routes()) > 0
