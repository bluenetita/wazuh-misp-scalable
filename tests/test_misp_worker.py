import importlib.util
import json
import os
import queue
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


try:
    import redis  # noqa: F401
except ModuleNotFoundError:
    redis_stub = types.ModuleType("redis")

    class RedisError(Exception):
        pass

    redis_stub.Redis = type("Redis", (), {})
    redis_stub.exceptions = types.SimpleNamespace(
        RedisError=RedisError,
        ResponseError=RedisError,
    )
    sys.modules["redis"] = redis_stub


os.environ["LOG_FILE"] = os.path.join(tempfile.gettempdir(), "misp-worker-tests.log")
sys.dont_write_bytecode = True
worker_path = Path(__file__).parents[1] / "worker" / "src" / "misp_worker.py"
worker_spec = importlib.util.spec_from_file_location("misp_worker", worker_path)
worker = importlib.util.module_from_spec(worker_spec)
worker_spec.loader.exec_module(worker)


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.acknowledgements = []
        self.operations = []
        self.claim_calls = []
        self.claim_responses = []
        self.fail_dlq = False

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def get(self, key):
        return self.values.get(key)

    def incr(self, key):
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]

    def expire(self, key, seconds):
        return key in self.values

    def delete(self, *keys):
        for key in keys:
            self.values.pop(key, None)

    def xack(self, stream, group, message_id):
        self.operations.append(("xack", message_id))
        self.acknowledgements.append((stream, group, message_id))
        return 1

    def xadd(self, stream, fields):
        if self.fail_dlq:
            raise worker.redis.exceptions.RedisError("DLQ unavailable")
        self.operations.append(("xadd", stream))
        return "1-0"

    def execute_command(self, *args):
        self.claim_calls.append(args)
        return self.claim_responses.pop(0)


class WorkerDeliveryTests(unittest.TestCase):
    def setUp(self):
        worker.stop_evt.clear()
        self.patchers = [
            mock.patch.object(worker, "ACK_ON_MISP_ERROR", True),
            mock.patch.object(worker, "DLQ_MAX_RETRIES", 3),
            mock.patch.object(worker, "circuit_breaker", worker.CircuitBreaker(0, 0)),
            mock.patch.object(worker, "get_session", return_value=object()),
            mock.patch.object(worker, "send_wazuh_event"),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self):
        worker.stop_evt.clear()
        for patcher in reversed(self.patchers):
            patcher.stop()

    @staticmethod
    def alert_fields():
        return {
            "alert": json.dumps({
                "data": {"fqdn": "example.com"},
                "rule": {"description": "test rule"},
            })
        }

    @staticmethod
    def extractor_config():
        return {
            "rules": [{
                "when": {},
                "extract": [{"type": "fqdn", "path": "data.fqdn"}],
            }]
        }

    def test_dlq_retries_take_precedence_over_ack_policy(self):
        redis_client = FakeRedis()
        with mock.patch.object(worker, "misp_query_value", side_effect=RuntimeError("MISP down")):
            counters = worker.process_message(
                redis_client, self.extractor_config(), "1-0", self.alert_fields()
            )

        self.assertEqual(0, counters[0])
        self.assertEqual([], redis_client.acknowledgements)
        self.assertEqual(1, redis_client.values[worker.k_retries("1-0")])

    def test_same_message_retry_bypasses_dedupe(self):
        redis_client = FakeRedis()
        worker.ACK_ON_MISP_ERROR = False
        with mock.patch.object(
            worker, "misp_query_value", side_effect=RuntimeError("MISP down")
        ) as misp_query:
            first = worker.process_message(
                redis_client, self.extractor_config(), "1-0", self.alert_fields()
            )
            second = worker.process_message(
                redis_client, self.extractor_config(), "1-0", self.alert_fields()
            )

        self.assertEqual(0, first[0])
        self.assertEqual(0, second[0])
        self.assertEqual(2, misp_query.call_count)
        self.assertEqual([], redis_client.acknowledgements)

    def test_failed_retry_bypasses_another_messages_dedupe_key(self):
        redis_client = FakeRedis()
        dedupe_key = worker.k_dedupe({"type": "fqdn", "value": "example.com"})
        with mock.patch.object(
            worker, "misp_query_value", side_effect=RuntimeError("MISP down")
        ) as misp_query:
            first = worker.process_message(
                redis_client, self.extractor_config(), "1-0", self.alert_fields()
            )
            redis_client.delete(dedupe_key)
            redis_client.set(dedupe_key, "2-0", nx=True, ex=worker.DEDUP_TTL)
            retry = worker.process_message(
                redis_client, self.extractor_config(), "1-0", self.alert_fields()
            )
            fresh = worker.process_message(
                redis_client, self.extractor_config(), "3-0", self.alert_fields()
            )

        self.assertEqual(0, first[0])
        self.assertEqual(0, retry[0])
        self.assertEqual(2, misp_query.call_count)
        self.assertEqual(2, redis_client.values[worker.k_retries("1-0")])
        self.assertEqual(1, fresh[0])
        self.assertEqual(
            [(worker.STREAM, worker.GROUP, "3-0")], redis_client.acknowledgements
        )

    def test_failed_dlq_write_leaves_source_pending(self):
        redis_client = FakeRedis()
        redis_client.fail_dlq = True
        worker.DLQ_MAX_RETRIES = 1
        with mock.patch.object(worker, "misp_query_value", side_effect=RuntimeError("MISP down")):
            counters = worker.process_message(
                redis_client, self.extractor_config(), "1-0", self.alert_fields()
            )

        self.assertEqual(0, counters[0])
        self.assertEqual(0, counters[7])
        self.assertEqual([], redis_client.acknowledgements)

    def test_successful_dlq_write_precedes_source_ack(self):
        redis_client = FakeRedis()
        worker.DLQ_MAX_RETRIES = 1
        with mock.patch.object(worker, "misp_query_value", side_effect=RuntimeError("MISP down")):
            counters = worker.process_message(
                redis_client, self.extractor_config(), "1-0", self.alert_fields()
            )

        self.assertEqual(1, counters[0])
        self.assertEqual(1, counters[7])
        self.assertEqual([("xadd", worker.DLQ_STREAM), ("xack", "1-0")], redis_client.operations)

    def test_ack_policy_still_applies_when_dlq_is_disabled(self):
        redis_client = FakeRedis()
        worker.DLQ_MAX_RETRIES = 0
        with mock.patch.object(worker, "misp_query_value", side_effect=RuntimeError("MISP down")):
            counters = worker.process_message(
                redis_client, self.extractor_config(), "1-0", self.alert_fields()
            )

        self.assertEqual(1, counters[0])
        self.assertEqual([(worker.STREAM, worker.GROUP, "1-0")], redis_client.acknowledgements)

    def test_non_object_json_is_logged_and_acknowledged(self):
        redis_client = FakeRedis()

        counters = worker.process_message(redis_client, {}, "1-0", {"alert": "[]"})

        self.assertEqual(1, counters[0])
        self.assertEqual(1, counters[6])
        self.assertEqual([(worker.STREAM, worker.GROUP, "1-0")], redis_client.acknowledgements)

    def test_xautoclaim_scan_advances_until_zero_cursor(self):
        redis_client = FakeRedis()
        redis_client.claim_responses = [
            ["2-0", [("1-0", {"alert": "first"})], []],
            ["0-0", [("2-0", {"alert": "second"})], []],
        ]

        messages = list(worker.xautoclaim_scan(redis_client, min_idle_ms=0, count=1))

        self.assertEqual(["1-0", "2-0"], [message_id for message_id, _ in messages])
        self.assertEqual(["0-0", "2-0"], [call[5] for call in redis_client.claim_calls])

    def test_half_open_admission_allows_exactly_one_probe(self):
        breaker = worker.CircuitBreaker(threshold=1, reset_sec=0)
        breaker.record_success()
        breaker.record_success()
        breaker.record_failure()

        self.assertEqual((True, True), breaker.admit_query())
        self.assertEqual((False, False), breaker.admit_query())
        breaker.release_probe()

    def test_reclaim_waits_for_circuit_recovery(self):
        breaker = worker.CircuitBreaker(threshold=1, reset_sec=60)
        with mock.patch.object(worker.time, "time", return_value=100):
            breaker.record_failure()

        with mock.patch.object(worker.time, "time", return_value=159):
            self.assertFalse(breaker.recovery_ready())

        with mock.patch.object(worker.time, "time", return_value=160):
            self.assertTrue(breaker.recovery_ready())
            self.assertEqual((True, True), breaker.admit_query())
            self.assertFalse(breaker.recovery_ready())

        breaker.record_success()
        breaker.release_probe()
        self.assertTrue(breaker.recovery_ready())

    def test_open_circuit_leaves_message_pending(self):
        redis_client = FakeRedis()
        breaker = worker.CircuitBreaker(threshold=1, reset_sec=60)
        breaker.record_failure()

        with mock.patch.object(worker, "circuit_breaker", breaker):
            with mock.patch.object(worker, "misp_query_value") as misp_query:
                counters = worker.process_message(
                    redis_client, self.extractor_config(), "1-0", self.alert_fields()
                )

        misp_query.assert_not_called()
        self.assertEqual((0, 1, 0, 0, 0, 0, 0, 0), counters)
        self.assertEqual([], redis_client.acknowledgements)
        self.assertNotIn(worker.k_retries("1-0"), redis_client.values)

    def test_circuit_deferred_retry_bypasses_another_messages_dedupe_key(self):
        redis_client = FakeRedis()
        breaker = worker.CircuitBreaker(threshold=1, reset_sec=60)
        breaker.record_failure()
        counters = worker.Counters()
        message_queue = queue.Queue()
        dedupe_key = worker.k_dedupe({"type": "fqdn", "value": "example.com"})

        with mock.patch.object(worker, "circuit_breaker", breaker):
            with mock.patch.object(worker, "misp_query_value", return_value=[]) as misp_query:
                deferred = worker.process_message(
                    redis_client, self.extractor_config(), "1-0", self.alert_fields()
                )
                redis_client.delete(dedupe_key)
                redis_client.set(dedupe_key, "2-0", nx=True, ex=worker.DEDUP_TTL)
                breaker.record_success()
                message_queue.put(("1-0", self.alert_fields(), True))
                worker.stop_evt.set()
                worker.worker_loop(
                    "test", message_queue, redis_client,
                    {"cfg": self.extractor_config()}, counters,
                )

        self.assertEqual(0, deferred[0])
        self.assertEqual(1, misp_query.call_count)
        self.assertEqual((1, 1, 0, 1, 1, 0, 0, 0), counters.snapshot_and_reset())
        self.assertEqual(
            [(worker.STREAM, worker.GROUP, "1-0")], redis_client.acknowledgements
        )
        self.assertNotIn(worker.k_retries("1-0"), redis_client.values)

    def test_unexpected_worker_error_does_not_ack(self):
        redis_client = FakeRedis()
        message_queue = queue.Queue()
        message_queue.put(("1-0", self.alert_fields(), False))
        counters = worker.Counters()
        worker.stop_evt.set()

        with mock.patch.object(worker, "process_message", side_effect=RuntimeError("unexpected")):
            with mock.patch.object(worker, "close_session"):
                worker.worker_loop(
                    "test", message_queue, redis_client,
                    {"cfg": self.extractor_config()}, counters,
                )

        snapshot = counters.snapshot_and_reset()
        self.assertEqual(0, snapshot[0])
        self.assertEqual(1, snapshot[6])
        self.assertEqual([], redis_client.acknowledgements)


if __name__ == "__main__":
    unittest.main()
