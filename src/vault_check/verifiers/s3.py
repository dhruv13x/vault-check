import asyncio
import logging
from urllib.parse import urlparse
import boto3
from botocore.exceptions import ClientError

from ..utils import mask_sensitive
from .base import BaseVerifier


class S3Verifier(BaseVerifier):
    async def verify(
        self,
        bucket_name: str,
        region: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        endpoint_url: str | None = None,  # For generic S3 compatible (MinIO, R2)
        **kwargs
    ) -> None:
        """
        Verifies S3 bucket existence and accessibility.
        
        Can accept explicit credentials or fall back to environment/boto3 default resolution.
        Can accept a bucket name or an s3:// URL.
        """
        
        # Handle s3:// URL if passed as bucket_name
        if bucket_name and bucket_name.startswith("s3://"):
            parsed = urlparse(bucket_name)
            bucket_name = parsed.netloc
        
        logging.info(f"Checking [bold]S3 Bucket[/bold]: {bucket_name}")

        if not bucket_name:
            raise ValueError("Bucket name is required")

        def _check_s3():
            # Initialize session/client
            # If keys are None, boto3 uses env vars (AWS_ACCESS_KEY_ID, etc.) or ~/.aws/credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            
            s3 = session.client("s3", endpoint_url=endpoint_url)
            
            try:
                # Head Bucket is the cheapest check for existence & permission
                s3.head_bucket(Bucket=bucket_name)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code")
                if error_code == "403":
                    raise PermissionError(f"Access Denied to bucket '{bucket_name}'")
                elif error_code == "404":
                    raise FileNotFoundError(f"Bucket '{bucket_name}' does not exist")
                else:
                    raise e

        loop = asyncio.get_running_loop()
        # Run blocking boto3 in executor to not block the async loop
        await loop.run_in_executor(None, _check_s3)
