import sys
from unittest.mock import patch
from vault_check.__main__ import main

def test_main_function_entry_point():
    # Patch sys.argv to simulate no arguments
    with patch("sys.argv", ["vault-check", "--version"]):
        # We need to patch the entry_point function that is imported in __main__.py
        with patch("vault_check.__main__.entry_point") as mock_ep:
            main()
            mock_ep.assert_called_once()

def test_if_name_main():
    import runpy
    # Patch sys.argv
    with patch("sys.argv", ["vault-check", "--version"]):
        # When runpy executes, it imports from .cli
        with patch("vault_check.cli.entry_point") as mock_ep:
            try:
                runpy.run_module("vault_check.__main__", run_name="__main__")
            except SystemExit:
                pass

            # Since the real entry_point might have run if patch failed to propagate (unlikely if done right),
            # check call count.
            # If SystemExit(0) happened, it means the real code ran.
            # But we patched vault_check.cli.entry_point.

            mock_ep.assert_called_once()
