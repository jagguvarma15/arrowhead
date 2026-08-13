"""OAuth 2.1 resource server wiring.

Arrowhead never issues tokens. An external authorization server does that;
this server only verifies the bearer token on every request through the
JWKS verifier: signature against the issuer's key material, issuer,
expiry, and audience. Incoming bearer tokens are never forwarded to
outbound requests.

RFC 9728 protected-resource metadata is served under /.well-known/ by the
SDK so clients can discover the authorization server. TLS is expected to
be terminated by the hosting platform or a reverse proxy in front of this
process; never expose the plain HTTP port directly in production.

Two provider paths are supported, both verified by the same in-house
verifier. The default "jwt" path takes any OAuth 2.1 issuer's key material
(a JWKS URI or a static public key), for bring-your-own-IdP. The "workos"
path derives the issuer and JWKS URI from an AuthKit domain; it is
configuration sugar over the jwt path, and the token audience defaults to
this server's public URL as AuthKit mints it.
"""

from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl

from arrowhead.auth.verifier import JWKSTokenVerifier
from arrowhead.config import Settings


def build_auth(
    settings: Settings, *, http_client=None
) -> tuple[JWKSTokenVerifier, AuthSettings] | None:
    """The token verifier and auth settings, or None when auth is off.

    Auth is off only for local stdio development. http_client is an optional
    injection point so a test can serve a JWKS document to the verifier.
    """
    if not settings.auth_enabled:
        return None
    if settings.oauth_provider == "workos":
        return _build_workos(settings, http_client)
    return _build_jwt(settings, http_client)


def _build_jwt(settings: Settings, http_client):
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
    verifier = JWKSTokenVerifier(
        issuer=settings.oauth_issuer,
        audience=settings.oauth_audience,
        jwks_uri=settings.oauth_jwks_uri,
        public_key=settings.oauth_public_key,
        http_client=http_client,
    )
    return verifier, _auth_settings(settings.oauth_issuer, settings)


def _build_workos(settings: Settings, http_client):
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
    domain = settings.oauth_authkit_domain.removeprefix("https://").strip("/")
    issuer = f"https://{domain}"
    verifier = JWKSTokenVerifier(
        issuer=issuer,
        audience=settings.oauth_audience or settings.server_public_url,
        jwks_uri=f"{issuer}/oauth2/jwks",
        http_client=http_client,
    )
    return verifier, _auth_settings(issuer, settings)


def _auth_settings(issuer: str, settings: Settings) -> AuthSettings:
    # The resource identifier is the MCP endpoint itself, so RFC 9728
    # metadata is served at /.well-known/oauth-protected-resource/mcp and
    # the 401 challenge points exactly there. The metadata deliberately
    # advertises no scope list: scopes are discovered through the filtered
    # tool listing a caller is entitled to, never through an
    # unauthenticated probe.
    base = settings.server_public_url.rstrip("/")
    return AuthSettings(
        issuer_url=AnyHttpUrl(issuer),
        resource_server_url=AnyHttpUrl(f"{base}/mcp"),
    )
