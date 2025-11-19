from __future__ import annotations

import asyncio
import subprocess

import pytest


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_e2e_success():
    """Verify that the E2E tests pass with valid credentials."""
    process = await asyncio.create_subprocess_exec(
        "sudo",
        "docker",
        "compose",
        "run",
        "--rm",
        "-T",
        "test",
        "vault-check",
        "--env-file",
        "tests/e2e/e2e.env",
        "--verifiers",
        "database",
        "redis",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    assert (
        process.returncode == 0
    ), f"stdout: {stdout.decode()}\\nstderr: {stderr.decode()}"


@pytest.mark.asyncio
@pytest.mark.timeout(120)
async def test_e2e_failure():
    """Verify that the E2E tests fail with invalid credentials."""
    process = await asyncio.create_subprocess_exec(
        "sudo",
        "docker",
        "compose",
        "run",
        "--rm",
        "-T",
        "test",
        "vault-check",
        "--env-file",
        "tests/e2e/invalid.env",
        "--verifiers",
        "database",
        "redis",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    assert (
        process.returncode != 0
    ), f"stdout: {stdout.decode()}\\nstderr: {stderr.decode()}"
