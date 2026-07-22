"""Authorization enforcement point for the document tools.

Each document tool calls authorize_action after validating its input and
before touching the corpus. Identity comes from the validated token via
caller_identity, never from an argument. A denial raises AuthorizationError
(a ToolError), so the audit middleware records it as a refusal and the
client sees a clean message that never echoes the resource identifier.
"""

from functools import lru_cache

from fastmcp.exceptions import ToolError

from arrowhead.auth.identity import caller_identity
from arrowhead.authz.policy import Authorizer, Resource, build_authorizer
from arrowhead.config import current_settings_override, get_settings


class AuthorizationError(ToolError):
    """The caller is not authorized for this resource."""


@lru_cache
def _env_authorizer() -> Authorizer:
    return build_authorizer(get_settings())


def get_authorizer() -> Authorizer:
    """The authorizer for the settings in effect for the current call.

    Under an injected settings block the authorizer is built from those
    settings so an embedding host's policy takes effect; otherwise the
    process-wide authorizer is built once and reused.
    """
    if current_settings_override() is not None:
        return build_authorizer(get_settings())
    return _env_authorizer()


# Keep the clear-the-cache affordance the environment-driven path relies on.
get_authorizer.cache_clear = _env_authorizer.cache_clear


def authorize_action(action: str, resource: Resource) -> str:
    """Authorize the current caller for an action on a resource.

    Returns the caller's identity on success (useful for namespacing), and
    raises AuthorizationError on denial.
    """
    subject = caller_identity()
    decision = get_authorizer().authorize(subject, action, resource)
    if not decision.allowed:
        raise AuthorizationError("not authorized for this document")
    return subject
