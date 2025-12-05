import importlib.metadata
import logging
from .registry import VerifierRegistry

def load_plugins(registry: VerifierRegistry) -> None:
    """
    Loads verifier plugins from the 'vault_check.plugins' entry point group.

    Each plugin is expected to expose a function that accepts a VerifierRegistry.
    """
    try:
        # For Python 3.10+
        entry_points = importlib.metadata.entry_points(group="vault_check.plugins")
    except TypeError:
        # Fallback for older Python versions if necessary (not needed for 3.11+)
        entry_points = importlib.metadata.entry_points().get("vault_check.plugins", [])

    for entry_point in entry_points:
        try:
            plugin_func = entry_point.load()
            if callable(plugin_func):
                plugin_func(registry)
                logging.info(f"Loaded plugin: {entry_point.name}")
            else:
                logging.warning(f"Plugin {entry_point.name} is not callable")
        except Exception as e:
            logging.warning(f"Failed to load plugin {entry_point.name}: {e}")
