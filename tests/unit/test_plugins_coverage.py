
import pytest
from unittest.mock import MagicMock, patch
from vault_check.plugins import load_plugins

def test_load_plugins_success():
    mock_entry_point = MagicMock()
    mock_entry_point.name = "test_plugin"
    mock_plugin = MagicMock()
    mock_entry_point.load.return_value = mock_plugin

    # Mock importlib.metadata.entry_points for Python 3.10+
    # Note: verify_secrets.py (now vault_check) uses Python 3.11+, so group kwarg is supported.
    with patch("importlib.metadata.entry_points") as mock_entry_points:
        mock_entry_points.return_value = [mock_entry_point]

        registry = MagicMock()
        load_plugins(registry)

        # Check that entry_points was called correctly
        mock_entry_points.assert_called_with(group="vault_check.plugins")

        # Check plugin execution
        mock_plugin.assert_called_once_with(registry)

def test_load_plugins_not_callable():
    mock_entry_point = MagicMock()
    mock_entry_point.name = "bad_plugin"
    mock_entry_point.load.return_value = "not_callable"

    with patch("importlib.metadata.entry_points") as mock_entry_points:
        mock_entry_points.return_value = [mock_entry_point]

        registry = MagicMock()
        load_plugins(registry)

        # Should not crash, effectively no-op on registry
        registry.add.assert_not_called()

def test_load_plugins_exception():
    mock_entry_point = MagicMock()
    mock_entry_point.name = "crasher"
    mock_entry_point.load.side_effect = Exception("Boom")

    with patch("importlib.metadata.entry_points") as mock_entry_points:
        mock_entry_points.return_value = [mock_entry_point]

        registry = MagicMock()
        load_plugins(registry)
        # Should catch exception and log warning
