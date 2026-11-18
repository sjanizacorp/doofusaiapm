"""Fail-closed caller for DoofusAI's inline screening endpoint."""
import json
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from gcs import NoRedirect


class ScreeningError(Exception):
    """The application must withhold the original content."""


class RuntimeClient:
    def __init__(self, origin, token, *, timeout=3):
        url = urlsplit(origin)
        if (not url.hostname or url.path not in ("", "/") or url.username or url.password or url.query
                or url.fragment or url.scheme not in ("http", "https")
                or (url.scheme == "http" and url.hostname not in ("127.0.0.1", "::1", "localhost"))):
            raise ValueError("Use the trusted screening service HTTPS origin or a local loopback origin.")
        if not isinstance(token, str) or not token or any(char.isspace() for char in token):
            raise ValueError("A runtime credential is required.")
        if not 0 < timeout <= 30:
            raise ValueError("Screening timeout must be positive and at most 30 seconds.")
        self.origin = origin.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = build_opener(NoRedirect())

    def _post(self, route, data):
        try:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        except UnicodeError:
            raise ScreeningError("Screening input must contain valid Unicode text.") from None
        if len(body) > 8192:
            raise ScreeningError("Content exceeds inline screening limits.")
        request = Request(self.origin + route, data=body, headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + self.token,
        })
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError()
            result = json.loads(raw)
        except (OSError, ValueError, RecursionError):
            raise ScreeningError("Screening did not produce a usable decision.") from None
        if not isinstance(result, dict):
            raise ScreeningError("Screening did not produce a usable decision.")
        return result

    def screen(self, text, *, action="redact"):
        """Return the only content the caller is permitted to forward."""
        if not isinstance(text, str) or len(text) > 6000 or action not in ("redact", "block"):
            raise ScreeningError("Invalid screening input.")
        result = self._post("/api/v1/runtime/inspect", {"text": text, "action": action})
        decision, signals = result.get("decision"), result.get("signals")
        if not isinstance(signals, dict) or any(type(count) is not int or count < 1 for count in signals.values()):
            raise ScreeningError("Screening did not produce a usable decision.")
        if decision == "allow" and not signals and "text" not in result:
            return text
        if decision == "redact" and action == "redact" and signals and isinstance(result.get("text"), str):
            return result["text"]
        if decision == "block":
            raise ScreeningError("Content blocked by screening policy.")
        raise ScreeningError("Screening did not produce a usable decision.")

    def authorize_tool(self, *, agent, tool, operation, target):
        """Return only on explicit allow. Enforce this before invoking the tool."""
        args = {"agent": agent, "tool": tool, "operation": operation, "target": target}
        if any(not isinstance(value, str) or not value or len(value) > 80 for value in args.values()):
            raise ScreeningError("Invalid tool coordinates.")
        if self._post("/api/v1/runtime/authorize-tool", args) != {"decision": "allow"}:
            raise ScreeningError("Agent tool call was not authorized.")

    def authorize_model(self, *, agent, model):
        args = {"agent": agent, "model": model}
        if any(not isinstance(value, str) or not value or len(value) > 80 for value in args.values()):
            raise ScreeningError("Invalid agent or model identifier.")
        if self._post("/api/v1/runtime/authorize-model", args) != {"decision": "allow"}:
            raise ScreeningError("Agent model invocation was not authorized.")


class GuardedTools:
    """Execute only application-registered handlers after authorization and screening."""

    def __init__(self, *, agent, authorizer, screening, handlers):
        self.agent = agent
        self.authorizer = authorizer
        self.screening = screening
        self.handlers = dict(handlers)

    def invoke(self, *, tool, operation, target, text):
        if any(not isinstance(value, str) for value in (tool, operation, target)):
            raise ScreeningError("Invalid tool coordinates.")
        handler = self.handlers.get((tool, operation, target))
        if handler is None:
            raise ScreeningError("Tool handler is not registered.")
        self.authorizer.authorize_tool(agent=self.agent, tool=tool, operation=operation, target=target)
        inbound = self.screening.screen(text, action="block")
        response = handler(inbound)
        self.authorizer.authorize_tool(agent=self.agent, tool=tool, operation=operation, target=target)
        return self.screening.screen(response, action="block")
