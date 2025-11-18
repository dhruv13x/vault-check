from __future__ import annotations

import os
import subprocess
import time

import pytest


@pytest.fixture(scope="module")
def redis_service():
    # Start the redis container
    subprocess.run(
        ["docker", "compose", "-f", "tests/e2e/docker-compose.yml", "up", "-d"],
        check=True,
    )
    # Give it a moment to start
    time.sleep(2)
    yield
    # Stop the redis container
    subprocess.run(
        ["docker", "compose", "-f", "tests/e2e/docker-compose.yml", "down"], check=True
    )


@pytest.mark.skip(reason="Docker permission error in CI")
def test_e2e_redis_verifier_success(redis_service):
    env_content = "CORE_PLATFORM_REDIS_URL=redis://localhost:6379/0"
    with open(".env", "w") as f:
        f.write(env_content)

    result = subprocess.run(
        ["vault-check", "--skip-live=false"],
        capture_output=True,
        text=True,
    )

    os.remove(".env")

    assert "PASSED" in result.stdout
    assert "Core Platform Redis connected" in result.stdout
    assert result.returncode == 0
