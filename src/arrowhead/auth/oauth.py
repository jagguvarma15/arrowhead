"""OAuth 2.1 resource server.

Arrowhead never issues tokens. An external authorization server does that;
this server only verifies the bearer token on every request: signature
against the issuer's key material, issuer, expiry, and, critically, that
the token's audience names this server. A token minted for some other
service is refused even when its signature, issuer, and expiry are all
valid, which is what stops a stolen or confused token from being replayed
here. Incoming bearer tokens are never forwarded to outbound requests.

RFC 9728 protected-resource metadata is served under /.well-known/ so
clients can discover the authorization server. TLS is expected to be
terminated by the hosting platform or a reverse proxy in front of this
process; never expose the plain HTTP port directly in production.
"""

from pydantic import AnyHttpUrl

from arrowhead.auth.scopes import supported_scopes
from arrowhead.config import Settings


def build_auth_provider(settings: Settings):
    """Build the auth provider from settings, or None when auth is off.

    Auth is off only for local stdio development. When enabled, issuer,
    audience, the server's public URL, and one source of key material
    (JWKS URI or a static public key) are all required.
    """
    if not settings.auth_enabled:
        return None

    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    missing = [
        name
        for name, value in {
            "ARROWHEAD_OAUTH_ISSUER": settings.oauth_issuer,
            "ARROWHEAD_OAUTH_AUDIENCE": settings.oauth_audience,
            "ARROWHEAD_SERVER_PUBLIC_URL": settings.server_public_url,
        }.items()
        if not value
    ]
    if not settings.oauth_jwks_uri and not settings.oauth_public_key:
        missing.append("ARROWHEAD_OAUTH_JWKS_URI or ARROWHEAD_OAUTH_PUBLIC_KEY")
    if missing:
        raise ValueError(
            "auth is enabled but configuration is incomplete: "
            + ", ".join(missing)
        )

    verifier = JWTVerifier(
        jwks_uri=settings.oauth_jwks_uri,
        public_key=settings.oauth_public_key,
        issuer=settings.oauth_issuer,
        audience=settings.oauth_audience,
    )
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[AnyHttpUrl(settings.oauth_issuer)],
        base_url=settings.server_public_url,
        resource_name="arrowhead",
        scopes_supported=supported_scopes(),
    )
