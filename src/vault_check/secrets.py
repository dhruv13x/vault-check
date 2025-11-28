# src/vault_check/secrets.py

from __future__ import annotations

import logging
import os
from typing import Any, Dict

import boto3

from .config import SECRET_KEYS
from .http_client import HTTPClient
from .utils import get_secret_value


async def load_secrets(
    http: HTTPClient,
    aws_ssm_prefix: str | None = None,
    doppler_project: str = "default_project",
    doppler_config: str = "dev",
    dry_run: bool = False,
    include_all: bool = False,
) -> Dict[str, Any]:
    secrets: Dict[str, Any] = {}
    doppler_token = os.getenv("DOPPLER_TOKEN")
    aws_ssm_client = None

    if aws_ssm_prefix:
        try:
            aws_ssm_client = boto3.client("ssm")
            logging.info("Using AWS SSM for secrets")
        except Exception as e:
            logging.warning(f"AWS SSM init failed: {e}; falling back")

    if doppler_token and not dry_run:
        doppler_url = f"https://api.doppler.com/v3/configs/config/secrets?project={doppler_project}&config={doppler_config}"
        try:
            data = await http.get_json(
                doppler_url, headers={"Authorization": f"Bearer {doppler_token}"}
            )
            if not isinstance(data, dict):
                raise ValueError("Unexpected Doppler response type")
            secrets = data.get("secrets", data)
            logging.info(f"Doppler secrets fetched (count={len(secrets)})")
        except Exception as e:
            logging.warning(f"Doppler fetch failed: {e}; using .env")
    elif aws_ssm_client:
        try:
            for key in SECRET_KEYS:
                param_name = f"{aws_ssm_prefix}/{key}"
                param = aws_ssm_client.get_parameter(Name=param_name, WithDecryption=True)
                secrets[key] = param["Parameter"]["Value"]
            logging.info(f"AWS SSM secrets fetched (count={len(secrets)})")
        except Exception as e:
            logging.warning(f"AWS SSM fetch failed: {e}; using .env")

    if include_all:
        # Start with local env
        merged = os.environ.copy()
        # Overlay remote secrets (they take precedence or just add to the pool?
        # Standard pattern: Remote overrides Local for overlapping keys.
        # `secrets` contains the remote ones.
        merged.update(secrets)
        
        # However, we must ensure get_secret_value() logic is respected if used later.
        # But here we are returning raw values mostly.
        # The existing return logic was:
        # {k: get_secret_value(secrets, k) or os.getenv(k) for k in SECRET_KEYS}
        # get_secret_value checks `secrets` dict.
        
        # So `merged` is effectively the superset.
        return merged

    return {k: get_secret_value(secrets, k) or os.getenv(k) for k in SECRET_KEYS}
