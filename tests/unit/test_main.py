from unittest.mock import patch

from vault_check.__main__ import main


def test_main():
    with patch("vault_check.__main__.entry_point") as mock_entry_point:
        main()
        mock_entry_point.assert_called_once()
