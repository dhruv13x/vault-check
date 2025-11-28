import pytest
from unittest.mock import MagicMock, patch
import smtplib
import socket
from vault_check.verifiers.smtp import SMTPVerifier

@pytest.mark.asyncio
async def test_smtp_verifier_success():
    verifier = SMTPVerifier()
    
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value = mock_smtp
        
        await verifier.verify("smtp.example.com", port=587)
        
        mock_smtp_cls.assert_called_with("smtp.example.com", 587, timeout=10)
        mock_smtp.ehlo.assert_called()
        mock_smtp.quit.assert_called()

@pytest.mark.asyncio
async def test_smtp_verifier_ssl_success():
    verifier = SMTPVerifier()
    
    with patch("smtplib.SMTP_SSL") as mock_smtp_ssl_cls:
        mock_smtp = MagicMock()
        mock_smtp_ssl_cls.return_value = mock_smtp
        
        await verifier.verify("smtp.example.com", port=465)
        
        mock_smtp_ssl_cls.assert_called_with("smtp.example.com", 465, timeout=10)
        mock_smtp.ehlo.assert_called()
        mock_smtp.quit.assert_called()

@pytest.mark.asyncio
async def test_smtp_verifier_auth_success():
    verifier = SMTPVerifier()
    
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value = mock_smtp
        mock_smtp.has_extn.return_value = True
        
        await verifier.verify("smtp.example.com", username="user", password="pass")
        
        mock_smtp.starttls.assert_called()
        mock_smtp.login.assert_called_with("user", "pass")

@pytest.mark.asyncio
async def test_smtp_verifier_connection_error():
    verifier = SMTPVerifier()
    
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_smtp_cls.side_effect = socket.gaierror("Name or service not known")
        
        with pytest.raises(ConnectionError, match="Could not connect"):
            await verifier.verify("smtp.example.com")

@pytest.mark.asyncio
async def test_smtp_verifier_auth_error():
    verifier = SMTPVerifier()
    
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value = mock_smtp
        mock_smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, "Auth failed")
        
        with pytest.raises(PermissionError, match="SMTP Authentication failed"):
            await verifier.verify("smtp.example.com", username="user", password="badpass")

@pytest.mark.asyncio
async def test_smtp_verifier_url_parsing():
    verifier = SMTPVerifier()
    
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value = mock_smtp
        
        await verifier.verify("smtp://user:pass@smtp.mailgun.org:2525")
        
        mock_smtp_cls.assert_called_with("smtp.mailgun.org", 2525, timeout=10)
        mock_smtp.login.assert_called_with("user", "pass")
