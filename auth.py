"""OAuth 2.1 + PKCE flow helper for agent authentication.

Used when agents authenticate via authorization code flow
rather than direct token issuance.
"""

import base64
import hashlib
import secrets
from typing import Tuple


def generate_pkce_pair() -> Tuple[str, str]:
    """Generate a PKCE code_verifier and code_challenge pair.

    Returns (code_verifier, code_challenge) for use in OAuth 2.1 + PKCE flows.
    """
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def build_authorize_url(
    authorize_endpoint: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    scope: str = "",
    state: str = "",
) -> str:
    """Build the OAuth 2.1 authorization URL with PKCE parameters."""
    from urllib.parse import urlencode

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if scope:
        params["scope"] = scope
    if state:
        params["state"] = state
    else:
        params["state"] = secrets.token_urlsafe(16)

    return f"{authorize_endpoint}?{urlencode(params)}"
