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

Two provider paths are supported. The default "jwt" path verifies bearer
tokens against any OAuth 2.1 issuer's key material (a JWKS URI or a static
public key), for bring-your-own-IdP. The "workos" path wires WorkOS
AuthKit, which is purpose-built for MCP: it validates tokens against WorkOS
and serves the metadata MCP clients need for automatic registration.
"""

from pydantic import AnyHttpUrl

from arrowhead.auth.scopes import supported_scopes
from arrowhead.config import Settings


def build_auth_provider(settings: Settings, *, http_client=None):
    """Build the auth provider from settings, or None when auth is off.

    Auth is off only for local stdio development. http_client is an optional
    injection point so a test can serve a JWKS document to the JWT verifier.
    """
    if not settings.auth_enabled:
        return None
    if settings.oauth_provider == "workos":
        return _build_workos_provider(settings)
    return _build_jwt_provider(settings, http_client)


def _build_jwt_provider(settings: Settings, http_client):
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
        http_client=http_client,
    )
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[AnyHttpUrl(settings.oauth_issuer)],
        base_url=settings.server_public_url,
        resource_name="arrowhead",
        scopes_supported=supported_scopes(),
    )


def _build_workos_provider(settings: Settings):
    from fastmcp.server.auth.providers.workos import AuthKitProvider

    missing = [
        name
        for name, value in {
            "ARROWHEAD_OAUTH_AUTHKIT_DOMAIN": settings.oauth_authkit_domain,
            "ARROWHEAD_SERVER_PUBLIC_URL": settings.server_public_url,
        }.items()
        if not value
    ]
    if missing:
        raise ValueError(
            "workos auth is enabled but configuration is incomplete: "
            + ", ".join(missing)
        )
    return AuthKitProvider(
        authkit_domain=settings.oauth_authkit_domain,
        base_url=settings.server_public_url,
        scopes_supported=supported_scopes(),
        resource_name="arrowhead",
    )
