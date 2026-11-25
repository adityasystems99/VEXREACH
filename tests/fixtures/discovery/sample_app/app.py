"""Minimal sample application fixture for Discovery Engine testing (never executed)."""

import requests


def fetch_status(url: str) -> int:
    response = requests.get(url, timeout=5)
    return response.status_code
