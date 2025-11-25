# tests/unit/test_cli_coverage.py

import sys
import pytest
from unittest.mock import patch, MagicMock
from vault_check.cli import entry_point, main

@patch("vault_check.cli.print")
def test_cli_version_flag(mock_print):
    # Simulate --version
    with patch("sys.argv", ["vault-check", "--version"]):
        # entry_point calls asyncio.run(main(sys.argv[1:]))
        # But we can call main directly if we want, or entry_point.
        # entry_point calls sys.exit, so we need to catch it.
        with pytest.raises(SystemExit) as exc:
            entry_point()
        assert exc.value.code == 0
        mock_print.assert_called()

def test_cli_keyboard_interrupt():
    # Simulate KeyboardInterrupt during main execution
    with patch("vault_check.cli.asyncio.run", side_effect=KeyboardInterrupt):
        with patch("sys.argv", ["vault-check"]):
            with pytest.raises(SystemExit) as exc:
                entry_point()
            assert exc.value.code == 130

@pytest.mark.asyncio
async def test_cli_main_version_flag():
    # Test main function directly
    with patch("builtins.print") as mock_print:
        exit_code = await main(["--version"])
        assert exit_code == 0
        mock_print.assert_called()
