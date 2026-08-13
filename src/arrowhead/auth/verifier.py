"""Bearer-token verification against an external issuer's key material.

Implements the SDK's TokenVerifier protocol with pyjwt. Verification
checks the signature against the issuer's JWKS (or a static public key),
the issuer, the expiry, and, critically, that the token's audience names
this server: a token minted for some other service is refused even when
its signature, issuer, and expiry are all valid, which is what stops a
stolen or confused token from being replayed here.

JWKS keys are cached by key id with a bounded lifetime, and a token
naming an unknown key id triggers at most one extra fetch per cache
window, so routine issuer key rotation works without a restart while a
stream of fabricated key ids cannot turn the verifier into a request
amplifier. Every failure path returns None, which the SDK surfaces as an
ordinary 401 challenge; no verification detail leaks to the caller.
"""

import time

import httpx
import jwt
from mcp.server.auth.provider import AccessToken

_ALGORITHMS = ("RS256", "ES256")


class JWKSTokenVerifier:
    """Verify bearer JWTs against a JWKS endpoint or a static public key."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_uri: str | None = None,
        public_key: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        algorithms: tuple[str, ...] = _ALGORITHMS,
        cache_ttl_seconds: float = 300.0,
        clock=time.monotonic,
    ) -> None:
        if not jwks_uri and not public_key:
            raise ValueError("a JWKS URI or a static public key is required")
        self._issuer = issuer
        self._audience = audience
        self._jwks_uri = jwks_uri
        self._public_key = public_key
        self._http_client = http_client
        self._algorithms = list(algorithms)
        self._cache_ttl = cache_ttl_seconds
        self._clock = clock
        self._keys: dict[str, object] = {}
        self._fetched_at: float | None = None
        self._rotation_used = False

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            key = await self._key_for(token)
            if key is None:
                return None
            claims = jwt.decode(
                token,
                key=key,
                algorithms=self._algorithms,
                issuer=self._issuer,
                audience=self._audience,
                options={"require": ["exp", "iss", "aud"]},
            )
        except (jwt.PyJWTError, httpx.HTTPError, ValueError, KeyError):
            return None
        subject = claims.get("sub") or ""
        return AccessToken(
            token=token,
            client_id=claims.get("client_id") or subject,
            subject=subject or None,
            scopes=_scopes(claims),
            expires_at=claims.get("exp"),
        )

    async def _key_for(self, token: str):
        """The verification key for the token's header, or None."""
        if self._public_key:
            return self._public_key
        kid = jwt.get_unverified_header(token).get("kid")
        if kid is None:
            return None
        now = self._clock()
        expired = (
            self._fetched_at is None or now - self._fetched_at > self._cache_ttl
        )
        if expired:
            await self._refresh()
            self._fetched_at = now
            self._rotation_used = False
        if kid not in self._keys and not self._rotation_used:
            # One extra fetch per cache window picks up a genuine key
            # rotation immediately; a fabricated key id spends the window's
            # single retry and every later one fails from cache.
            self._rotation_used = True
            await self._refresh()
        return self._keys.get(kid)

    async def _refresh(self) -> None:
        client = self._http_client
        if client is None:
            async with httpx.AsyncClient(timeout=10.0) as owned:
                document = await self._fetch_jwks(owned)
        else:
            document = await self._fetch_jwks(client)
        keys: dict[str, object] = {}
        for entry in document.get("keys", []):
            kid = entry.get("kid")
            if not kid:
                continue
            try:
                keys[kid] = jwt.PyJWK(entry).key
            except jwt.PyJWTError:
                continue
        self._keys = keys

    async def _fetch_jwks(self, client: httpx.AsyncClient) -> dict:
        if self._jwks_uri is None:
            raise ValueError("no JWKS URI configured")
        response = await client.get(self._jwks_uri)
        response.raise_for_status()
        document = response.json()
        if not isinstance(document, dict):
            raise ValueError("JWKS document is not an object")
        return document


def _scopes(claims: dict) -> list[str]:
    """Scopes from the standard space-separated claim, or the scp list."""
    scope = claims.get("scope")
    if isinstance(scope, str):
        return [entry for entry in scope.split() if entry]
    scp = claims.get("scp")
    if isinstance(scp, list):
        return [entry for entry in scp if isinstance(entry, str) and entry]
    return []
