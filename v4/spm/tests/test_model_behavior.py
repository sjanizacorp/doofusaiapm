import hashlib
import json
import unittest
from unittest.mock import Mock

from model_behavior import ChatDeployment, ChatError, GuardedChat, evaluate, load_suite
from controls import Problem
from runtime_client import ScreeningError


def suite(*cases):
    return json.dumps({"schema": "doofusai.behavior.v1", "cases": cases}).encode()


def response(text, *, finish="stop", tool_calls=None):
    message = {"role": "assistant", "content": text}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return json.dumps({"choices": [{"message": message, "finish_reason": finish}]}).encode()


class BehavioralTest(unittest.TestCase):
    def test_fixed_suite_reports_outcomes_without_recording_inputs_or_responses(self):
        data = suite(
            {"id": "structured", "input": "synthetic catalog prompt", "expect": {"json_keys": ["status"]}},
            {"id": "redaction", "input": "synthetic privacy prompt", "expect": {
                "absent": ["TEST-PRIVATE"], "max_chars": 20,
            }},
        )
        deployment = Mock(model="fixture-model")
        deployment.answer.side_effect = ['{"status":"ok"}', "unexpected test-private value"]
        outcome = evaluate(data, deployment)
        self.assertFalse(outcome["passed"])
        self.assertEqual(outcome["suite_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(outcome["cases"][1]["failed_checks"], ["absent", "max_chars"])
        rendered = json.dumps(outcome)
        self.assertNotIn("synthetic", rendered)
        self.assertNotIn("unexpected test-private value", rendered)

    def test_truncated_and_tool_responses_fail_closed(self):
        opener = Mock()
        entered = opener.open.return_value
        entered.__enter__ = Mock(return_value=entered)
        entered.__exit__ = Mock()
        instance = ChatDeployment("https://model.example.test", "named-model", opener=opener)
        for packet in (response("ok", finish="length"),
                       response("ok", tool_calls=[{"id": "fixture-tool"}])):
            entered.read.return_value = packet
            with self.assertRaises(ChatError):
                instance.answer("synthetic prompt")
        entered.read.return_value = response("ok")
        self.assertEqual(instance.answer("approved text"), "ok")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://model.example.test/v1/chat/completions")
        self.assertEqual(json.loads(request.data)["model"], "named-model")

    def test_suite_rejects_duplicate_ids_and_nonliteral_checks(self):
        case = {"id": "repeat", "input": "fixture", "expect": {"equal": "expected"}}
        with self.assertRaises(Problem):
            load_suite(suite(case, case))
        with self.assertRaises(Problem):
            load_suite(suite(case | {"expect": {"regex": "not supported"}}))

    def test_guarded_chat_checks_model_and_both_content_directions(self):
        deploy = Mock()
        authorizer = Mock()
        screening = Mock()
        screening.screen.side_effect = ["scrubbed input", "scrubbed output"]
        deploy.answer.return_value = "raw response"
        client = GuardedChat(deploy, authorizer=authorizer, screening=screening,
                             agent="pilot", model_node="approved", action="redact")
        self.assertEqual(client.answer("raw input"), "scrubbed output")
        authorizer.authorize_model.assert_called_once_with(agent="pilot", model="approved")
        deploy.answer.assert_called_once_with("scrubbed input")
        self.assertEqual([entry.args[0] for entry in screening.screen.call_args_list],
                         ["raw input", "raw response"])
        authorizer.authorize_model.side_effect = ScreeningError("blocked")
        with self.assertRaises(ScreeningError):
            client.answer("unapproved input")
        self.assertEqual(deploy.answer.call_count, 1)
