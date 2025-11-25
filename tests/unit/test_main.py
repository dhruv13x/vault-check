# tests/unit/test_main.py

from unittest.mock import patch

from vault_check.__main__ import main


def test_main():
    with patch("vault_check.__main__.entry_point") as mock_entry_point:
        main()
        mock_entry_point.assert_called_once()
# tests/unit/test_main.py

from unittest.mock import patch

import pytest

from vault_check.__main__ import main


@patch("vault_check.__main__.entry_point")
def test_main(mock_entry_point):
    """Verify that the main function calls the entry point."""
    main()
    mock_entry_point.assert_called_once()
