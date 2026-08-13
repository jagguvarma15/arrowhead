"""Authorization enforcement point for the document tools.

Each document tool calls authorize_action after validating its input and
before touching the corpus. Identity comes from the validated token via
caller_identity, never from an argument. A denial raises AuthorizationError
(a ToolError), so the audit middleware records it as a refusal and the
client sees a clean message that never echoes the resource identifier.
"""

from functools import lru_cache

from arrowhead.auth.identity import caller_identity
from arrowhead.authz.policy import (
    KIND_DOCUMENT,
    KIND_FILE,
    KIND_PREFIX,
    KIND_TABLE,
    KIND_TABLELESS,
    KIND_URL,
    Authorizer,
    Resource,
    build_authorizer,
)
from arrowhead.config import current_settings_override, get_settings
from arrowhead.errors import ToolError

# The noun used in a denial message, chosen from the resource kind so the
# message reads correctly for a URL or a table without ever echoing the
# resource identifier a probing caller supplied.
_RESOURCE_NOUN = {
    KIND_DOCUMENT: "document",
    KIND_PREFIX: "path",
    KIND_URL: "URL",
    KIND_TABLE: "table",
    KIND_TABLELESS: "query",
    KIND_FILE: "file",
}


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
        noun = _RESOURCE_NOUN.get(resource.kind, "resource")
        raise AuthorizationError(f"not authorized for this {noun}")
    return subject
