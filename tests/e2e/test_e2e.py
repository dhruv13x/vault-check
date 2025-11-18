import shutil
import subprocess
import time

import pytest

DOCKER_COMPOSE_COMMAND = shutil.which("docker-compose")


@pytest.fixture(scope="module")
def mock_environment():
    if not DOCKER_COMPOSE_COMMAND:
        pytest.skip("docker-compose not found, skipping e2e tests")
    subprocess.run([DOCKER_COMPOSE_COMMAND, "up", "-d"], check=True)
    # Give the services time to start up
    time.sleep(5)
    yield
    subprocess.run([DOCKER_COMPOSE_COMMAND, "down"], check=True)


def test_e2e_success(mock_environment):
    result = subprocess.run(
        [
            "vault-check",
            "--env-file",
            "tests/e2e/e2e.env",
            "--skip-live=false",
            "--dry-run=false",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Core Platform DB connected" in result.stdout
    assert "Heavy Worker Redis connected" in result.stdout
