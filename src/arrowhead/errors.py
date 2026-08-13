"""The refusal exception every guard and tool raises.

ToolError is the one exception type whose message is deliberately written
for the caller: a refusal (kill switch, rate limit, scope, authorization,
validation) or a safe failure summary. The dispatch boundary re-raises it
verbatim and masks every other exception, so text reaches a client only
when a guard or tool composed it on purpose.

The class extends the SDK's own tool error so anything in the server
runtime that special-cases tool errors treats ours the same way.
"""

from mcp.server.mcpserver.exceptions import ToolError as _SDKToolError


class ToolError(_SDKToolError):
    """A refusal or deliberate failure whose message is safe to return."""
