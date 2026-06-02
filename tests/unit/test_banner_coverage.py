
import pytest
import os
from unittest.mock import patch, MagicMock
from vault_check.banner import print_logo

def test_print_logo_default():
    with patch("rich.console.Console") as MockConsole:
        mock_instance = MockConsole.return_value
        print_logo()
        assert mock_instance.print.called

def test_print_logo_fixed_palette():
    with patch.dict(os.environ, {"CREATE_DUMP_PALETTE": "0"}):
        with patch("rich.console.Console") as MockConsole:
            mock_instance = MockConsole.return_value
            print_logo()
            assert mock_instance.print.called

def test_print_logo_invalid_palette():
    with patch.dict(os.environ, {"CREATE_DUMP_PALETTE": "999"}):
        with patch("rich.console.Console") as MockConsole:
            mock_instance = MockConsole.return_value
            print_logo()
            assert mock_instance.print.called

def test_print_logo_bad_env():
    with patch.dict(os.environ, {"CREATE_DUMP_PALETTE": "abc"}):
        with patch("rich.console.Console") as MockConsole:
            mock_instance = MockConsole.return_value
            print_logo()
            assert mock_instance.print.called

def test_print_logo_warm_cool_bias():
    # Patch random.SystemRandom.random to return 0.1, ensuring the branch
    # `if _sysrand.random() < 0.25:` is always executed.
    with patch("random.SystemRandom.random", return_value=0.1):
        with patch("rich.console.Console") as MockConsole:
            mock_instance = MockConsole.return_value
            print_logo()
            assert mock_instance.print.called

