import pytest
from unittest.mock import MagicMock, patch
from vault_check.registry import VerifierRegistry

# We expect this import to fail initially or the function to be missing
try:
    from vault_check.plugins import load_plugins
except ImportError:
    load_plugins = None

def test_load_plugins_finds_and_registers_plugins():
    if load_plugins is None:
        pytest.fail("load_plugins could not be imported")

    registry = VerifierRegistry()

    # Create a mock plugin function
    mock_plugin_func = MagicMock()

    # Create a mock entry point
    mock_entry_point = MagicMock()
    mock_entry_point.load.return_value = mock_plugin_func
    mock_entry_point.name = "test_plugin"

    # Mock importlib.metadata.entry_points
    # We patch it to return a list of entry points (or object with select for 3.10+)
    # Since we are using Python 3.11+, we need to handle how entry_points is called.
    # Usually entry_points(group='...') returns an EntryPoints object (iterable).

    with patch("importlib.metadata.entry_points") as mock_entry_points_func:
        mock_entry_points_func.return_value = [mock_entry_point]

        load_plugins(registry)

        # Verify call to entry_points with correct group
        mock_entry_points_func.assert_called_once_with(group="vault_check.plugins")

        # Verify the plugin was loaded
        mock_entry_point.load.assert_called_once()

        # Verify the plugin function was called with the registry
        mock_plugin_func.assert_called_once_with(registry)

def test_load_plugins_handles_exceptions():
    if load_plugins is None:
        pytest.fail("load_plugins could not be imported")

    registry = VerifierRegistry()

    mock_entry_point = MagicMock()
    mock_entry_point.load.side_effect = Exception("Load failed")
    mock_entry_point.name = "bad_plugin"

    with patch("importlib.metadata.entry_points") as mock_entry_points_func:
        mock_entry_points_func.return_value = [mock_entry_point]

        # Should not crash
        load_plugins(registry)

        mock_entry_point.load.assert_called_once()
