"""Auth pattern recognition across captured endpoints."""
from __future__ import annotations

import re


_BEARER_RE = re.compile(r'Bearer\s+\S+', re.IGNORECASE)
_APIKEY_RE = re.compile(r'(?:X-Api-Key|api[_-]key|x-token|x-auth-token)[:\s]+\S+', re.IGNORECASE)
_BASIC_RE  = re.compile(r'Basic\s+[A-Za-z0-9+/=]{8,}', re.IGNORECASE)
_JWT_RE    = re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')


class AuthDetector:
    """Detect auth scheme from endpoint headers and token values."""

    def detect(self, endpoint: dict) -> str:
        """Return detected auth type: 'bearer', 'apikey', 'basic', or 'none'."""
        # Check captured auth flag
        if not endpoint.get("auth"):
            return "none"

        # Check token values
        token = endpoint.get("token", "")
        if token:
            if _JWT_RE.match(token):
                return "bearer"
            if _BASIC_RE.match(token):
                return "basic"
            return "bearer"

        # Check request body for auth clues
        body = endpoint.get("request_body", {}) or {}
        if isinstance(body, dict):
            for key in body:
                if "token" in key.lower() or "auth" in key.lower():
                    return "bearer"

        return "bearer"  # Assume bearer if auth flag set

    def classify_all(self, endpoints: list[dict]) -> dict[str, str]:
        """Return {endpoint_key: auth_type} for all endpoints."""
        return {
            f"{ep['method']}:{ep.get('host','')}:{ep['path']}": self.detect(ep)
            for ep in endpoints
        }
