# tests/e2e/test_e2e.py
import subprocess

import pytest

# E2E tests require Docker and Docker Compose to be installed
# and the user to have permissions to run them.
# These tests are skipped by default.
# to run them, use `pytest --run-e2e`


@pytest.mark.skip(reason="Skipping e2e tests due to external dependencies")
def test_e2e_success():
    """
    Runs the verifier with a valid configuration and expects a successful exit code.
    """
    # build the docker image
    process = subprocess.run(
        "docker-compose build",
        shell=True,
        capture_output=True,
    )
    assert process.returncode == 0, f"stdout: {process.stdout.decode()} stderr: {process.stderr.decode()}"

    # run the verifier
    process = subprocess.run(
        "docker-compose run --rm test --log-level DEBUG --verifiers database redis",
        shell=True,
        capture_output=True,
    )
    assert (
        process.returncode == 0
    ), f"stdout: {process.stdout.decode()} stderr: {process.stderr.decode()}"


@pytest.mark.skip(reason="Skipping e2e tests due to external dependencies")
def test_e2e_failure():
    """
    Runs the verifier with an invalid configuration and expects a failure exit code.
    """
    # build the docker image
    process = subprocess.run(
        "docker-compose build",
        shell=True,
        capture_output=True,
    )
    assert process.returncode == 0, f"stdout: {process.stdout.decode()} stderr: {process.stderr.decode()}"

    # run the verifier
    process = subprocess.run(
        "docker-compose run --rm -e CORE_PLATFORM_DB_URL=invalid_db_url test --log-level DEBUG --verifiers database",
        shell=True,
        capture_output=True,
    )

    # exit code should be 2, as this indicates a verification failure
    assert (
        process.returncode == 2
    ), f"stdout: {process.stdout.decode()} stderr: {process.stderr.decode()}"
