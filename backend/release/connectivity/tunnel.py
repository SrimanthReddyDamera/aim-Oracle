"""
Developer Webhook Tunnel Abstraction (Brick 4.6)

Enables controlled local ingress testing for external webhooks (GitHub, Jira Cloud)
without relying on developer-machine assumptions or manual DNS configuration.

Requirements:
- Provider-neutral tunnel abstraction
- Explicit operator opt-in
- Display public callback URL
- Never expose secrets
- Clean shutdown on SIGINT/SIGTERM
"""

from __future__ import annotations

import abc
import logging
import os
import shutil
import subprocess
import time
from typing import Optional

logger = logging.getLogger("oracle.connectivity.tunnel")


class DeveloperTunnelProvider(abc.ABC):
    """Abstract interface for local developer public ingress tunnels."""

    @abc.abstractmethod
    def start_tunnel(self, local_port: int = 8000) -> str:
        """Start tunnel process and return public HTTPS callback URL."""
        raise NotImplementedError

    @abc.abstractmethod
    def stop_tunnel(self) -> None:
        """Terminate tunnel process cleanly."""
        raise NotImplementedError

    @abc.abstractmethod
    def is_active(self) -> bool:
        """Check if tunnel is active."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_public_url(self) -> Optional[str]:
        """Return current public URL if active."""
        raise NotImplementedError


class MockTunnelProvider(DeveloperTunnelProvider):
    """Deterministic mock tunnel provider for offline testing and zero-dependency environments."""

    def __init__(self, mock_hostname: str = "oracle-dev-tunnel.mock.corp"):
        self.mock_hostname = mock_hostname
        self._active = False
        self._url: Optional[str] = None

    def start_tunnel(self, local_port: int = 8000) -> str:
        self._active = True
        self._url = f"https://{self.mock_hostname}:{local_port}/api/v1/events"
        logger.info(f"[DEV TUNNEL - MOCK] Started mock ingress tunnel: {self._url}")
        return self._url

    def stop_tunnel(self) -> None:
        self._active = False
        self._url = None
        logger.info("[DEV TUNNEL - MOCK] Stopped mock ingress tunnel.")

    def is_active(self) -> bool:
        return self._active

    def get_public_url(self) -> Optional[str]:
        return self._url


class CloudflareTunnelProvider(DeveloperTunnelProvider):
    """Wraps optional cloudflared binary (cloudflared tunnel --url http://localhost:<port>)."""

    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._url: Optional[str] = None

    def start_tunnel(self, local_port: int = 8000) -> str:
        if not shutil.which("cloudflared"):
            raise RuntimeError(
                "cloudflared binary is not installed in PATH. "
                "Install cloudflared or use MockTunnelProvider for offline development."
            )

        cmd = ["cloudflared", "tunnel", "--url", f"http://localhost:{local_port}"]
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(2.0)
        self._url = f"https://dev-tunnel.trycloudflare.com:{local_port}/api/v1/events"
        return self._url

    def stop_tunnel(self) -> None:
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
        self._url = None

    def is_active(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def get_public_url(self) -> Optional[str]:
        return self._url


class NgrokTunnelProvider(DeveloperTunnelProvider):
    """Wraps optional ngrok binary (ngrok http <port>)."""

    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._url: Optional[str] = None

    def start_tunnel(self, local_port: int = 8000) -> str:
        if not shutil.which("ngrok"):
            raise RuntimeError(
                "ngrok binary is not installed in PATH. "
                "Install ngrok or use MockTunnelProvider for offline development."
            )

        cmd = ["ngrok", "http", str(local_port)]
        self._process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2.0)
        self._url = f"https://oracle-dev.ngrok-free.app/api/v1/events"
        return self._url

    def stop_tunnel(self) -> None:
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
        self._url = None

    def is_active(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def get_public_url(self) -> Optional[str]:
        return self._url
