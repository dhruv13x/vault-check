# src/vault_check/secrets.py

from __future__ import annotations

import logging
import os
from typing import Any, Dict

import boto3
import hvac  # type: ignore

from .config import SECRET_KEYS
from .http_client import HTTPClient
from .utils import get_secret_value


async def load_secrets(
    http: HTTPClient,
    aws_ssm_prefix: str | None = None,
    doppler_project: str = "bot-platform",
    doppler_config: str = "dev_bot-platform",
    dry_run: bool = False,
    include_all: bool = False,
    initial_doppler_token: str | None = None,
) -> Dict[str, Any]:
    secrets: Dict[str, Any] = {}
    doppler_token = os.getenv("DOPPLER_TOKEN")
    vault_addr = os.getenv("VAULT_ADDR")
    vault_token = os.getenv("VAULT_TOKEN")
    aws_ssm_client = None

    if aws_ssm_prefix:
        try:
            aws_ssm_client = boto3.client("ssm")
            logging.info("Using AWS SSM for secrets")
        except Exception as e:
            logging.warning(f"AWS SSM init failed: {e}; falling back")

    if vault_addr and vault_token and not dry_run:
        try:
            client = hvac.Client(url=vault_addr, token=vault_token)
            if client.is_authenticated():
                user_path = os.getenv("VAULT_PATH", "secret/data/app")

                # Simplified approach: We expect VAULT_PATH to be the path relative to the mount point (often "secret")
                # but many users might provide "secret/data/app".
                # We strip "secret/data/" or "secret/" to get the path for read_secret_version
                # which usually expects path relative to mount.

                # clear "secret/data/"
                secret_path = user_path.replace("secret/data/", "").replace("secret/", "")

                read_response = client.secrets.kv.v2.read_secret_version(path=secret_path)
                secrets = read_response["data"]["data"]
                logging.info(f"HashiCorp Vault secrets fetched (count={len(secrets)})")
            else:
                logging.warning("HashiCorp Vault authentication failed")
        except Exception as e:
            logging.warning(f"HashiCorp Vault fetch failed: {e}; falling back")

    elif doppler_token and not dry_run:
        token_source = "env var" if initial_doppler_token else ".env file"
        doppler_url = f"https://api.doppler.com/v3/configs/config/secrets?project={doppler_project}&config={doppler_config}"
        try:
            data = await http.get_json(
                doppler_url, headers={"Authorization": f"Bearer {doppler_token}"}
            )
            if not isinstance(data, dict):
                raise ValueError("Unexpected Doppler response type")
            secrets = data.get("secrets", data)
            logging.info(f"Doppler secrets fetched using {token_source} (count={len(secrets)})")
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
        
        # Process secrets to ensure we have simple values (strings) not dicts
        processed_secrets = {}
        for k in secrets:
             val = get_secret_value(secrets, k)
             if val is not None:
                 processed_secrets[k] = val
        
        merged.update(processed_secrets)
        return merged

    return {k: get_secret_value(secrets, k) or os.getenv(k) for k in SECRET_KEYS}
