"""Deterministic owner admission tests: no model, GPU, service or HTTP listener."""
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from owner_control import OwnerControl, _Server
from openai_server import APIError, Engine, GenerationScheduler

LEASE = "a" * 64
OTHER = "b" * 64

class EngineEvidenceTest(unittest.TestCase):
    def test_a_failed_stop_write_cannot_masquerade_as_an_idle_empty_pending_map(self):
        engine = Engine.__new__(Engine)
        engine.pending_lock = threading.Lock()
        engine.write_lock = threading.Lock()
        engine.pending = {"1": object()}
        engine.unconfirmed = set()
        class BrokenPipe:
            def write(self, _data): raise BrokenPipeError("fixture")
        class Process:
            stdin = BrokenPipe()
        engine.process = Process()
        with self.assertRaises(RuntimeError):
            engine._write_frame("1", b"STOP 1\n", "STOP")
        self.assertEqual(engine.pending, {})
        self.assertEqual(engine.unconfirmed, {"1"})

class SchedulerDrainTest(unittest.TestCase):
    def test_existing_fifo_finishes_but_new_work_is_refused(self):
        scheduler = GenerationScheduler(max_queue=2, queue_timeout=5)
        first = scheduler.admit()
        first.__enter__()
        finished = threading.Event()
        def old_waiter():
            with scheduler.admit():
                finished.set()
        worker = threading.Thread(target=old_waiter)
        worker.start()
        with scheduler.condition:
            self.assertTrue(scheduler.condition.wait_for(lambda: len(scheduler.queue) == 1, 1))
        scheduler.begin_drain(LEASE)
        self.assertFalse(scheduler.wait_drained(LEASE, 0))
        with self.assertRaises(APIError) as refusal:
            with scheduler.admit():
                self.fail("new work entered during drain")
        self.assertEqual(refusal.exception.code, "scheduler_draining")
        scheduler.pause()
        scheduler.resume()  # watchdog recovery must not reopen owner admission
        with self.assertRaises(APIError):
            with scheduler.admit():
                self.fail("watchdog reopened owner admission")
        first.__exit__(None, None, None)
        self.assertTrue(finished.wait(1))
        worker.join(1)
        self.assertTrue(scheduler.wait_drained(LEASE, 1))
        self.assertEqual(scheduler.snapshot()["completed"], 2)
        with self.assertRaises(ValueError):
            scheduler.resume_drain(OTHER)
        scheduler.resume_drain(LEASE)
        with scheduler.admit():
            pass

    def test_timeout_retains_closed_admission_without_cancelling_active_work(self):
        scheduler = GenerationScheduler()
        with scheduler.admit():
            scheduler.begin_drain(LEASE)
            self.assertFalse(scheduler.wait_drained(LEASE, 0))
            self.assertEqual(scheduler.snapshot()["active"], 1)
            self.assertEqual(scheduler.snapshot()["cancelled"], 0)
            self.assertFalse(scheduler.snapshot()["accepting"])
        self.assertTrue(scheduler.wait_drained(LEASE, 0))

@unittest.skipUnless(sys.platform.startswith("linux"), "owner control requires Linux peer credentials")
class OwnerControlTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.scheduler = GenerationScheduler()
        self.identity = {"known": True, "pid": 123, "generation": 1, "pending": 0}
        self.control = OwnerControl(Path(self.directory.name).resolve(), self.scheduler, lambda: dict(self.identity))
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(lambda: self.control.close())

    def request(self, op, **fields):
        request = {"op": op, **fields}
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(3)
            connection.connect(str(self.control.path))
            connection.sendall(json.dumps(request).encode() + b"\n")
            return json.loads(connection.makefile("rb").readline())

    def drain(self, **fields):
        return self.request("drain", instance=self.control.instance, lease=LEASE, timeout_seconds=0, **fields)

    def test_peer_credentials_and_private_files_bound_control_to_process_owner(self):
        class Peer:
            def __init__(self, uid): self.uid = uid
            def getsockopt(self, *_): return struct.pack("3i", 1, self.uid, 1)
        self.assertTrue(_Server.verify_request(None, Peer(os.geteuid()), None))
        self.assertFalse(_Server.verify_request(None, Peer(os.geteuid() + 1), None))
        self.assertEqual(self.control.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.request("status")["instance"], self.control.instance)

    def test_exact_lease_and_process_instance_are_required_and_resume_is_reversible(self):
        result = self.drain()
        self.assertTrue(result["drained"])
        self.assertTrue(result["admission_closed"])
        self.assertEqual((result["active"], result["queued"]), (0, 0))
        for fields in ({"instance": "stale", "lease": LEASE},
                       {"instance": self.control.instance, "lease": OTHER}):
            self.assertFalse(self.request("resume", **fields)["ok"])
        self.assertTrue(self.request("resume", instance=self.control.instance, lease=LEASE)["ok"])
        self.assertTrue(self.scheduler.snapshot()["accepting"])
        self.assertFalse(self.request("resume", instance=self.control.instance, lease=LEASE)["ok"])

    def test_timeout_and_unknown_backend_never_claim_drain_or_cancel_work(self):
        with self.scheduler.admit():
            self.assertFalse(self.drain()["drained"])
            self.assertEqual(self.scheduler.snapshot()["active"], 1)
        self.identity["known"] = False
        self.assertFalse(self.drain()["drained"])
        self.identity.update(known=True, pending=1)
        self.assertFalse(self.drain()["drained"])
        self.identity["pending"] = 0
        self.assertTrue(self.drain()["drained"])
        self.assertEqual(self.scheduler.snapshot()["cancelled"], 0)

    def test_restart_keeps_admission_closed_and_invalidates_old_receipt_instance(self):
        old = self.drain()
        self.control.close()
        self.scheduler = GenerationScheduler()
        self.control = OwnerControl(Path(self.directory.name).resolve(), self.scheduler, lambda: dict(self.identity))
        self.assertNotEqual(old["instance"], self.control.instance)
        self.assertFalse(self.scheduler.snapshot()["accepting"])
        self.assertFalse(self.request("resume", instance=old["instance"], lease=LEASE)["ok"])
        self.assertTrue(self.request("resume", instance=self.control.instance, lease=LEASE)["ok"])

    def test_resume_between_wait_and_receipt_cannot_report_a_drained_lease(self):
        original = self.scheduler.wait_drained
        resumed = False
        def raced(*args):
            nonlocal resumed
            result = original(*args)
            if not resumed:
                resumed = True
                self.control.command({"op":"resume", "instance":self.control.instance, "lease":LEASE})
            return result
        with patch.object(self.scheduler, "wait_drained", side_effect=raced):
            with self.assertRaises(ValueError):
                self.control.command({"op":"drain", "instance":self.control.instance, "lease":LEASE, "timeout_seconds":0})
        self.assertTrue(self.scheduler.snapshot()["accepting"])

    def test_malformed_or_overbroad_control_is_refused(self):
        for body in ({"op": "stop"}, {"op": "status", "extra": True},
                     {"op": "drain", "instance": self.control.instance, "lease": LEASE, "timeout_seconds": 301},
                     {"op": "drain", "instance": self.control.instance, "lease": "invalid", "timeout_seconds": 0}):
            self.assertFalse(self.request(**body)["ok"])
        self.assertTrue(self.scheduler.snapshot()["accepting"])
