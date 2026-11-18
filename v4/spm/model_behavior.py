"""Evaluate an approved fixed suite against a single OpenAI-compatible chat deployment."""
import hashlib
import json
import re
from time import monotonic
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from controls import Problem
from gcs import NoRedirect
from verification import parse_json

MAX_SUITE = 512 * 1024
MAX_REPLY = 256 * 1024
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}")
CHECKS = {"equal", "contains", "absent", "json_keys", "max_chars"}


class ChatError(Exception):
    """The deployment did not return an eligible response."""


class ChatDeployment:
    def __init__(self, origin, model, token=None, *, timeout=10, opener=None):
        parts = urlsplit(origin)
        if (not parts.hostname or parts.path not in ("", "/") or parts.query or parts.fragment
                or parts.username or parts.password or (
                    parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in (
                        "127.0.0.1", "::1", "localhost",
                    ))
                )):
            raise Problem(400, "Use a trusted HTTPS deployment origin or a local loopback origin.")
        if (not isinstance(model, str) or not 1 <= len(model) <= 200 or not model.isprintable()
                or not 0 < timeout <= 30):
            raise Problem(400, "Use a valid model identifier and timeout of at most 30 seconds.")
        if token is not None and (not token or len(token) > 8192 or not token.isascii()
                                  or any(character.isspace() for character in token)):
            raise Problem(400, "Invalid model deployment credential.")
        self.endpoint = origin.rstrip("/") + "/v1/chat/completions"
        self.model = model
        self.token = token
        self.timeout = timeout
        self.opener = opener or build_opener(NoRedirect())

    def answer(self, message, *, stream=False):
        if not isinstance(message, str) or not 1 <= len(message) <= 6000:
            raise ChatError("Chat input is outside supported limits.")
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream" if stream else "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        document = {"model": self.model, "messages": [{"role": "user", "content": message}],
                    "max_tokens": 512, "stream": stream}
        try:
            payload = json.dumps(document, ensure_ascii=False).encode()
            request = Request(self.endpoint, data=payload, headers=headers)
            with self.opener.open(request, timeout=self.timeout) as response:
                if stream:
                    return buffered_stream(response, self.timeout)
                raw = response.read(MAX_REPLY + 1)
            if len(raw) > MAX_REPLY:
                raise ValueError()
            result = parse_json(raw)
            choice, = result["choices"]
            reply = choice["message"]
            text = reply.get("content")
            if (choice.get("finish_reason") != "stop" or reply.get("role") != "assistant"
                    or reply.get("tool_calls") or reply.get("function_call")
                    or not isinstance(text, str) or not text.strip() or len(text) > 6000):
                raise ValueError()
            text.encode("utf-8")
        except (OSError, ValueError, TypeError, KeyError, AttributeError, Problem):
            raise ChatError("Model did not return an eligible text response.") from None
        return text


def bounded_lines(response, deadline):
    pending = bytearray()
    size = 0
    while monotonic() < deadline:
        chunk = response.read1(8192)
        size += len(chunk)
        if not chunk or size > MAX_REPLY or monotonic() >= deadline:
            return
        pending.extend(chunk)
        while (end := pending.find(b"\n")) != -1:
            if end >= 16384:
                return
            yield bytes(pending[:end])
            del pending[:end + 1]
        if len(pending) >= 16384:
            return


def buffered_stream(response, timeout):
    """Collect a bounded text-only SSE response before any content can leave the gateway."""
    if response.headers.get_content_type() != "text/event-stream":
        raise ValueError("Unexpected upstream content type")
    deadline = monotonic() + timeout
    chunks, characters, stopped = [], 0, False
    for line in bounded_lines(response, deadline):
        line = line.rstrip(b"\r")
        if not line or line.startswith(b":"):
            continue
        if not line.startswith(b"data:"):
            break
        payload = line[5:].strip()
        if payload == b"[DONE]":
            if stopped and (text := "".join(chunks)).strip():
                return text
            break
        if stopped:
            break
        record = parse_json(payload)
        choice, = record["choices"]
        delta = choice["delta"]
        if (choice.get("index") != 0 or not isinstance(delta, dict)
                or delta.keys() - {"role", "content"} or delta.get("role", "assistant") != "assistant"):
            break
        text = delta.get("content")
        if text is not None:
            if not isinstance(text, str):
                break
            text.encode("utf-8")
            characters += len(text)
            if characters > 6000:
                break
            chunks.append(text)
        reason = choice.get("finish_reason")
        if reason not in (None, "stop"):
            break
        stopped = reason == "stop"
    raise ValueError("Incomplete or unsupported upstream stream")


def load_suite(raw):
    if len(raw) > MAX_SUITE:
        raise Problem(400, "Behavior suite exceeds the size limit.")
    document = parse_json(raw)
    if (not isinstance(document, dict) or document.keys() != {"schema", "cases"}
            or document["schema"] != "doofusai.behavior.v1"
            or not isinstance(document["cases"], list) or not 1 <= len(document["cases"]) <= 40):
        raise Problem(400, "Use a doofusai.behavior.v1 suite containing 1–40 cases.")
    ids = set()
    for case in document["cases"]:
        if not isinstance(case, dict) or case.keys() != {"id", "input", "expect"}:
            raise Problem(400, "Behavior cases require id, input and expect.")
        label, prompt, expected = (case[key] for key in ("id", "input", "expect"))
        if (not isinstance(label, str) or LABEL.fullmatch(label) is None or label in ids
                or not isinstance(prompt, str) or not 1 <= len(prompt) <= 6000
                or not isinstance(expected, dict) or not expected or expected.keys() - CHECKS):
            raise Problem(400, "Invalid behavior case or duplicate case ID.")
        ids.add(label)
        if "max_chars" in expected and (type(expected["max_chars"]) is not int
                                        or not 1 <= expected["max_chars"] <= 6000):
            raise Problem(400, "max_chars must be a number from 1 to 6000.")
        if "equal" in expected and (not isinstance(expected["equal"], str) or len(expected["equal"]) > 6000):
            raise Problem(400, "equal must contain a bounded expected response.")
        for kind in ("contains", "absent", "json_keys"):
            if kind not in expected:
                continue
            items = expected[kind]
            if (not isinstance(items, list) or not 1 <= len(items) <= 20
                    or any(not isinstance(item, str) or not 1 <= len(item) <= 512 for item in items)
                    or len(set(items)) != len(items)):
                raise Problem(400, f"{kind} must contain 1–20 unique nonempty strings.")
    return document["cases"]


def assess_output(response, expected):
    failed = []
    if "equal" in expected and response.strip() != expected["equal"]:
        failed.append("equal")
    if any(fragment not in response for fragment in expected.get("contains", [])):
        failed.append("contains")
    if any(fragment.casefold() in response.casefold() for fragment in expected.get("absent", [])):
        failed.append("absent")
    if "max_chars" in expected and len(response) > expected["max_chars"]:
        failed.append("max_chars")
    if "json_keys" in expected:
        try:
            document = parse_json(response)
        except Problem:
            document = None
        if not isinstance(document, dict) or document.keys() != set(expected["json_keys"]):
            failed.append("json_keys")
    return failed


def evaluate(raw, deployment):
    cases = load_suite(raw)
    results = []
    for case in cases:
        try:
            failed = assess_output(deployment.answer(case["input"]), case["expect"])
        except ChatError:
            failed = ["model-response-unavailable-or-unsupported"]
        results.append({"id": case["id"], "passed": not failed, "failed_checks": failed})
    return {"schema": "doofusai.behavior-result.v1", "suite_sha256": hashlib.sha256(raw).hexdigest(),
            "model": deployment.model, "passed": all(case["passed"] for case in results), "cases": results}


class GuardedChat:
    """An application integration with explicit routing and fail-closed screening."""
    def __init__(self, deployment, *, authorizer, screening, agent, model_node, action="block"):
        self.deployment = deployment
        self.authorizer = authorizer
        self.screening = screening
        self.agent = agent
        self.model_node = model_node
        self.action = action

    def answer(self, text):
        self.authorizer.authorize_model(agent=self.agent, model=self.model_node)
        guarded_input = self.screening.screen(text, action=self.action)
        response = self.deployment.answer(guarded_input)
        return self.screening.screen(response, action=self.action)
