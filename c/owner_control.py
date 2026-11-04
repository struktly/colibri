"""Optional Linux owner-only admission control, in the existing server process."""
import errno
try:
    import fcntl
except ImportError:
    fcntl = None
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import struct
import tempfile
import threading
import time
import uuid

LIMIT = 4096
SCHEMA = "colibri/owner-control/v1"


def _trusted(info, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("owner control requires private process-owned state")
    if not directory and info.st_nlink != 1:
        raise ValueError("owner control files require one link")


def _read_lease(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as source:
        _trusted(os.fstat(source.fileno()))
        raw = source.read(LIMIT + 1)
    value = json.loads(raw)
    if len(raw) > LIMIT or not isinstance(value, dict) or set(value) != {"lease"}:
        raise ValueError("invalid owner lease")
    _lease(value["lease"])
    return value["lease"]


def _lease(value):
    if not isinstance(value, str) or not re.fullmatch("[a-f0-9]{64}", value):
        raise ValueError("lease must be 64 lowercase hexadecimal characters")


if hasattr(socketserver, "ThreadingUnixStreamServer"):
    class _Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        block_on_close = False

        def verify_request(self, request, _address):
            # Filesystem permissions and kernel credentials are independent gates.
            try:
                _pid, uid, _gid = struct.unpack("3i", request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                return uid == os.geteuid()
            except OSError:
                return False

        def process_request(self, request, address):
            if not self.owner.clients.acquire(blocking=False):
                self.shutdown_request(request)
                return
            super().process_request(request, address)

        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                self.owner.clients.release()
else:
    _Server = None


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            raw = self.rfile.readline(LIMIT + 1)
            if len(raw) > LIMIT or not raw.endswith(b"\n"):
                raise ValueError("bounded newline-delimited JSON required")
            result = self.server.owner.command(json.loads(raw))
        except (ValueError, OSError, TimeoutError):
            result = {"schema": SCHEMA, "ok": False, "error": "owner control refused"}
        try:
            self.wfile.write(json.dumps(result).encode() + b"\n")
        except OSError:
            pass


class OwnerControl:
    """A scoped lease closes new admission durably; it never stops an engine."""
    def __init__(self, directory, scheduler, identity):
        if fcntl is None or _Server is None or not hasattr(socket, "SO_PEERCRED"):
            raise ValueError("owner control requires Linux peer credentials")
        self.directory = Path(directory)
        if not self.directory.is_absolute() or self.directory.resolve(strict=True) != self.directory:
            raise ValueError("owner control directory must be canonical and absolute")
        _trusted(self.directory.stat(), directory=True)
        self.scheduler, self.identity = scheduler, identity
        self.instance = uuid.uuid4().hex
        self.stopping = threading.Event()
        self.mutation = threading.Lock()
        self.clients = threading.BoundedSemaphore(4)
        self.lease_path = self.directory / "drain.json"
        fd = os.open(self.directory / "owner.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.lock = os.fdopen(fd, "rb")
        try:
            _trusted(os.fstat(fd))
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            lease = _read_lease(self.lease_path)
            if lease is not None:
                scheduler.begin_drain(lease)
            self.path = self.directory / "control.sock"
            if self.path.exists() or self.path.is_symlink():
                info = self.path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                    raise ValueError("unsafe owner socket")
                probe = socket.socket(socket.AF_UNIX)
                try:
                    probe.settimeout(0.2)
                    probe.connect(str(self.path))
                except OSError as error:
                    if error.errno != errno.ECONNREFUSED:
                        raise
                else:
                    raise ValueError("an owner socket is already listening")
                finally:
                    probe.close()
                self.path.unlink()
            self.server = _Server(str(self.path), _Handler)
            self.server.owner = self
            os.chmod(self.path, 0o600)
            self.socket_inode = self.path.stat().st_ino
            self.thread = threading.Thread(target=self.server.serve_forever, name="colibri-owner-control", daemon=True)
            self.thread.start()
        except BaseException:
            self.lock.close()
            raise

    def _sync_directory(self):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _persist(self, lease):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.directory, delete=False) as target:
                temporary = target.name
                target.write(json.dumps({"lease": lease}).encode())
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.lease_path)
            self._sync_directory()
        finally:
            if temporary is not None and os.path.exists(temporary):
                os.unlink(temporary)

    def status(self):
        snapshot = self.scheduler.snapshot()
        return {"schema": SCHEMA, "ok": True, "instance": self.instance, "pid": os.getpid(),
                "admission_closed": not snapshot["accepting"], "active": snapshot["active"],
                "queued": snapshot["queued"], "engine": self.identity()}

    def command(self, request):
        if not isinstance(request, dict) or request.get("op") not in {"status", "drain", "resume"}:
            raise ValueError("unknown owner operation")
        op = request["op"]
        allowed = {"op"} if op == "status" else {"op", "instance", "lease", "timeout_seconds"} if op == "drain" else {"op", "instance", "lease"}
        if set(request) != allowed:
            raise ValueError("unexpected owner operation fields")
        if op == "status":
            return self.status()
        if request["instance"] != self.instance:
            raise ValueError("owner instance changed")
        lease = request["lease"]
        _lease(lease)
        if op == "resume":
            with self.mutation:
                if _read_lease(self.lease_path) != lease:
                    raise ValueError("different lease owns admission")
                self.lease_path.unlink()
                self._sync_directory()
                self.scheduler.resume_drain(lease)
            return self.status()
        timeout = request["timeout_seconds"]
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 <= timeout <= 300:
            raise ValueError("drain timeout must be between zero and 300 seconds")
        with self.mutation:
            old = _read_lease(self.lease_path)
            if old is not None and old != lease:
                raise ValueError("different lease owns admission")
            # Persist before closing admission: a crash cannot reopen an acknowledged lease.
            self._persist(lease)
            self.scheduler.begin_drain(lease)
        deadline = time.monotonic() + timeout
        while not self.stopping.is_set():
            drained = self.scheduler.wait_drained(lease, max(0, deadline - time.monotonic()), self.stopping)
            with self.mutation:
                if _read_lease(self.lease_path) != lease:
                    raise ValueError("drain lease was released")
                drained = drained and self.scheduler.wait_drained(lease, 0, self.stopping)
                result = self.status()
                engine = result["engine"]
                if drained and result["admission_closed"] and result["active"] == 0 and result["queued"] == 0 and engine.get("known") is True and engine.get("pending") == 0:
                    return dict(result, drained=True, lease=lease)
                if not drained or engine.get("known") is not True or time.monotonic() >= deadline:
                    return dict(result, drained=False, lease=lease)
            self.stopping.wait(min(0.05, max(0, deadline - time.monotonic())))
        raise ValueError("owner control is stopping")

    def close(self):
        self.stopping.set()
        with self.scheduler.condition:
            self.scheduler.condition.notify_all()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)
        if self.path.is_socket() and self.path.stat().st_ino == self.socket_inode:
            self.path.unlink()
        self.lock.close()
