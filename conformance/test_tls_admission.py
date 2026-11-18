"""Exercise bounded handling of ordinary HTTPS reads and a Kubernetes health check."""

import http.client
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
from bounded_http import BoundedServer


class SlotObservation:
    """Observe when the listener meets a fully occupied pool. Keep the real semaphore."""

    def __init__(self, slots):
        self.slots = slots
        self.full = threading.Event()

    def acquire(self, *args, **kwargs):
        admitted = self.slots.acquire(*args, **kwargs)
        if not admitted:
            self.full.set()
        return admitted

    def release(self):
        self.slots.release()


def exercise_https_handoff(make_server):
    active = 0
    peak = 0
    changed = threading.Condition()
    finish_reads = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            nonlocal active, peak
            with changed:
                active += 1
                peak = max(peak, active)
                changed.notify_all()
            try:
                if self.path == "/read" and not finish_reads.wait(timeout=4):
                    self.send_error(503)
                    return
                self.send_response(200)
                self.send_header("Content-Length", "5")
                self.end_headers()
                self.wfile.write(b"ready")
            finally:
                with changed:
                    active -= 1

    with tempfile.TemporaryDirectory() as directory:
        cert = Path(directory) / "certificate.pem"
        key = Path(directory) / "private.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=local-fixture",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
        )
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(cert, key)
        client = ssl.create_default_context(cafile=str(cert))
        with make_server(Handler, tls) as server:
            observed = SlotObservation(server.slots)
            server.slots = observed
            serving = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.02}
            )
            serving.start()

            def get(path):
                connection = http.client.HTTPSConnection(
                    "127.0.0.1", server.server_port, context=client, timeout=4
                )
                try:
                    connection.request("GET", path)
                    reply = connection.getresponse()
                    return reply.status, reply.read()
                finally:
                    connection.close()

            try:
                with ThreadPoolExecutor(max_workers=5) as clients:
                    requests = [clients.submit(get, "/read") for _ in range(4)]
                    try:
                        with changed:
                            if not changed.wait_for(lambda: active == 4, timeout=3):
                                raise AssertionError(
                                    "Four ordinary reads did not enter their handlers"
                                )
                        health = clients.submit(get, "/health")
                        if not observed.full.wait(timeout=2):
                            raise AssertionError(
                                "The health check did not meet the four active workers"
                            )
                    finally:
                        finish_reads.set()
                    return (
                        [call.result(timeout=4) for call in requests],
                        health.result(timeout=4),
                        peak,
                    )
            finally:
                finish_reads.set()
                server.shutdown()
                serving.join(timeout=4)


class TlsAdmissionTests(unittest.TestCase):
    def test_worker_setup_failure_returns_its_slot(self):
        with BoundedServer(
            ("127.0.0.1", 0), BaseHTTPRequestHandler, workers=1
        ) as server:
            request, peer = socket.socketpair()
            address = ("127.0.0.1", 12345)
            with request, peer:
                with patch("socketserver.ThreadingMixIn.process_request"):
                    server.process_request(request, address)
                with patch.object(
                    socket.socket, "dup", side_effect=OSError("descriptor unavailable")
                ):
                    server.process_request_thread(request, address)
            self.assertTrue(server.slots.acquire(blocking=False))
            server.slots.release()

    def test_health_and_four_reads_share_bounded_tls_workers(self):
        def create(handler, tls):
            return BoundedServer(
                ("127.0.0.1", 0),
                handler,
                workers=4,
                timeout=5,
                tls=tls,
                wait_for_slot=True,
            )

        reads, health, peak = exercise_https_handoff(create)
        self.assertEqual(reads, [(200, b"ready")] * 4)
        self.assertEqual(health, (200, b"ready"))
        self.assertEqual(peak, 4)

    def test_waiting_preserves_the_original_connection_budget(self):
        with BoundedServer(
            ("127.0.0.1", 0),
            BaseHTTPRequestHandler,
            workers=1,
            timeout=1,
            wait_for_slot=True,
        ) as server:
            address = ("127.0.0.1", 12345)
            for worker_start, remaining in ((10.4, 0.6), (11.1, None)):
                request, peer = socket.socketpair()
                with self.subTest(worker_start=worker_start), request, peer:
                    with (
                        patch("bounded_http.time.monotonic", return_value=10.0),
                        patch("socketserver.ThreadingMixIn.process_request"),
                    ):
                        server.process_request(request, address)
                    with (
                        patch("bounded_http.time.monotonic", return_value=worker_start),
                        patch.object(server, "_serve_until") as handler,
                    ):
                        server.process_request_thread(request, address)
                    if remaining is None:
                        handler.assert_not_called()
                    else:
                        handler.assert_called_once()
                        sock, caller, deadline = handler.call_args.args
                        self.assertIs(sock, request)
                        self.assertEqual(caller, address)
                        self.assertEqual(deadline, 11.0)
                        self.assertAlmostEqual(request.gettimeout(), remaining)
                self.assertTrue(server.slots.acquire(blocking=False))
                server.slots.release()
