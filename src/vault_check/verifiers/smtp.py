import asyncio
import logging
import smtplib
import socket
from urllib.parse import urlparse

from ..utils import mask_url
from .base import BaseVerifier


class SMTPVerifier(BaseVerifier):
    async def verify(
        self,
        host: str,
        port: int | str = 587,
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = True,
        **kwargs
    ) -> None:
        """
        Verifies SMTP connectivity and authentication.
        """
        # Handle smtp:// URL if passed as host
        # e.g. smtp://user:pass@smtp.sendgrid.net:587
        if host and (host.startswith("smtp://") or host.startswith("smtps://")):
            parsed = urlparse(host)
            host = parsed.hostname
            if parsed.port:
                port = parsed.port
            if parsed.username:
                username = parsed.username
            if parsed.password:
                password = parsed.password
            if parsed.scheme == "smtps":
                use_tls = True # Implicitly SSL usually, usually port 465
                if not parsed.port:
                    port = 465

        logging.info(f"Checking [bold]SMTP[/bold] {host}:{port}")

        if not host:
            raise ValueError("SMTP Host is required")

        port = int(port)

        def _check_smtp():
            try:
                # Connect
                if port == 465:
                     # Implicit SSL
                    server = smtplib.SMTP_SSL(host, port, timeout=10)
                else:
                    server = smtplib.SMTP(host, port, timeout=10)
                
                try:
                    # Handshake
                    server.ehlo()
                    
                    # STARTTLS
                    if use_tls and port != 465:
                        if server.has_extn("STARTTLS"):
                            server.starttls()
                            server.ehlo()
                        else:
                            logging.warning("SMTP server does not support STARTTLS, skipping upgrade")

                    # Auth
                    if username and password:
                        server.login(username, password)
                        logging.info("SMTP Authentication Successful")
                    
                finally:
                    server.quit()
            except (socket.gaierror, ConnectionRefusedError, TimeoutError) as e:
                raise ConnectionError(f"Could not connect to SMTP server {host}:{port} - {e}")
            except smtplib.SMTPAuthenticationError:
                raise PermissionError("SMTP Authentication failed")
            except Exception as e:
                raise e

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _check_smtp)
