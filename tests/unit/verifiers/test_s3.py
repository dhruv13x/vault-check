import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from vault_check.verifiers.s3 import S3Verifier

@pytest.mark.asyncio
async def test_s3_verifier_success():
    verifier = S3Verifier()
    
    with patch("boto3.Session") as mock_session_cls:
        mock_s3 = MagicMock()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_s3
        mock_session_cls.return_value = mock_session
        
        await verifier.verify("my-bucket")
        
        mock_s3.head_bucket.assert_called_with(Bucket="my-bucket")

@pytest.mark.asyncio
async def test_s3_verifier_s3_url():
    verifier = S3Verifier()
    
    with patch("boto3.Session") as mock_session_cls:
        mock_s3 = MagicMock()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_s3
        mock_session_cls.return_value = mock_session
        
        await verifier.verify("s3://my-bucket")
        
        mock_s3.head_bucket.assert_called_with(Bucket="my-bucket")

@pytest.mark.asyncio
async def test_s3_verifier_not_exist():
    verifier = S3Verifier()
    
    with patch("boto3.Session") as mock_session_cls:
        mock_s3 = MagicMock()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_s3
        mock_session_cls.return_value = mock_session
        
        error_response = {'Error': {'Code': '404', 'Message': 'Not Found'}}
        mock_s3.head_bucket.side_effect = ClientError(error_response, 'HeadBucket')
        
        with pytest.raises(FileNotFoundError, match="does not exist"):
            await verifier.verify("my-bucket")

@pytest.mark.asyncio
async def test_s3_verifier_access_denied():
    verifier = S3Verifier()
    
    with patch("boto3.Session") as mock_session_cls:
        mock_s3 = MagicMock()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_s3
        mock_session_cls.return_value = mock_session
        
        error_response = {'Error': {'Code': '403', 'Message': 'Forbidden'}}
        mock_s3.head_bucket.side_effect = ClientError(error_response, 'HeadBucket')
        
        with pytest.raises(PermissionError, match="Access Denied"):
            await verifier.verify("my-bucket")
