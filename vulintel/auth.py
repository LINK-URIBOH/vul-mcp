import asyncio
import hashlib
import time

import httpx
import jwt
from mcp.server.auth.provider import AccessToken

from .config import settings


class Verifier:
    def __init__(self, cfg=None):
        self.cfg = cfg or settings()
        self.keys = {}
        self.loaded = 0.0
        self.lock = asyncio.Lock()

    async def key(self, kid):
        async with self.lock:
            # Bounded refresh also prevents an unknown-kid request flood causing unlimited JWKS requests.
            if time.monotonic() - self.loaded > 60 or not self.keys:
                async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                    response = await client.get(self.cfg.keycloak_internal_url + "/protocol/openid-connect/certs")
                    response.raise_for_status()
                    self.keys = {key["kid"]: jwt.PyJWK.from_dict(key).key for key in response.json()["keys"]
                                 if key.get("kty") == "RSA" and key.get("use", "sig") == "sig"}
                    self.loaded = time.monotonic()
        if kid not in self.keys:
            raise jwt.InvalidTokenError("Unknown signing key")
        return self.keys[kid]

    async def decode(self, token, audience):
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256":
            raise jwt.InvalidTokenError("Unexpected signing algorithm")
        key = await self.key(header.get("kid"))
        return jwt.decode(token, key, algorithms=["RS256"], audience=audience,
                          issuer=self.cfg.issuer_url, leeway=15,
                          options={"require": ["exp", "iat", "iss", "sub", "aud"]})

    async def verify_token(self, token):
        try:
            claims = await self.decode(token, self.cfg.resource_url)
            scopes = claims.get("scope", "").split()
            roles = claims.get("realm_access", {}).get("roles", [])
            if self.cfg.admin_role not in roles or claims.get("azp") != self.cfg.mcp_client_id:
                return None
            return AccessToken(token=token, client_id=claims["azp"], scopes=scopes,
                               expires_at=int(claims["exp"]), subject=claims["sub"],
                               resource=self.cfg.resource_url, claims={"iss": claims["iss"]})
        except (jwt.PyJWTError, httpx.HTTPError, KeyError, ValueError):
            return None


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def challenge(cfg=None):
    cfg = cfg or settings()
    return f'Bearer resource_metadata="{cfg.public_base_url}/.well-known/oauth-protected-resource/mcp"'
