import os
import sys
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from vault_check.cli import main

@pytest.mark.asyncio
async def test_cli_project_path_argument():
    """Test that a positional project path argument is accepted and used."""
    
    # Mock aiohttp and runner to avoid actual execution
    with patch("vault_check.cli.aiohttp.ClientSession") as mock_session, \
         patch("vault_check.cli.Runner") as mock_runner_cls, \
         patch("vault_check.cli.load_secrets", new_callable=AsyncMock) as mock_load_secrets:
        
        mock_runner = mock_runner_cls.return_value
        mock_runner.run = AsyncMock(return_value=0)
        mock_load_secrets.return_value = {}
        
        # Create a dummy directory and .env file
        with patch("os.path.isdir", return_value=True), \
             patch("vault_check.cli.load_dotenv") as mock_load_dotenv:
            
            # Run with a project path
            argv = ["/tmp/my_project"]
            exit_code = await main(argv)
            
            assert exit_code == 0
            
            # Check if load_dotenv was called with the joined path
            expected_path = os.path.join("/tmp/my_project", ".env")
            mock_load_dotenv.assert_called_with(expected_path)

@pytest.mark.asyncio
async def test_cli_invalid_project_path():
    """Test that an invalid project path results in an error."""
    
    with patch("os.path.isdir", return_value=False):
        argv = ["/invalid/path"]
        
        # Capture stdout/stderr if needed, but main returns 1 on error
        with patch("sys.stderr.write"):
            exit_code = await main(argv)
            assert exit_code == 1
