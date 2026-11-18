"""HTTP workers with bounded admission, bounded reads and optional per-worker TLS."""

import socket
import threading
import time
from http.server import HTTPServer
from socketserver import ThreadingMixIn


class BoundedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, *, workers=4, timeout=5, tls=None, wait_for_slot=False):
        if workers < 1 or timeout <= 0:
            raise ValueError("positive admission and time budgets required")
        self.slots = threading.BoundedSemaphore(workers)
        self.request_queue_size = workers
        self.io_timeout = timeout
        self.tls = tls
        self.wait_for_slot = wait_for_slot
        self._deadlines = {}
        self._deadline_lock = threading.Lock()
        super().__init__(address, handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self.io_timeout)
        return request, address

    def process_request(self, request, address):
        deadline = time.monotonic() + self.io_timeout if self.wait_for_slot else None
        admitted = self.slots.acquire(blocking=False)
        if not admitted and deadline is not None:
            # Only the accept loop can wait here. The worker and listen-queue limits stay fixed.
            admitted = self.slots.acquire(timeout=max(0, deadline - time.monotonic()))
        if not admitted:
            if self.tls is None:
                try:
                    request.settimeout(0.1)
                    request.sendall(
                        b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                except OSError:
                    pass
            self.shutdown_request(request)
            return
        try:
            if deadline is not None:
                with self._deadline_lock:
                    self._deadlines[request] = deadline
            super().process_request(request, address)
        except BaseException:
            if deadline is not None:
                with self._deadline_lock:
                    self._deadlines.pop(request, None)
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            if self.wait_for_slot:
                with self._deadline_lock:
                    deadline = self._deadlines.pop(request)
            else:
                deadline = time.monotonic() + self.io_timeout
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.shutdown_request(request)
                return
            request.settimeout(remaining)
            self._serve_until(request, address, deadline)
        except (OSError, RuntimeError):
            self.shutdown_request(request)
        finally:
            self.slots.release()

    def _serve_until(self, request, address, deadline):
        # A socket's timeout restarts after each received byte. A duplicate fd
        # lets the absolute connection budget also bound incremental reads and TLS.
        with request.dup() as watchdog_socket:
            finished = threading.Event()

            def expire():
                if not finished.wait(max(0, deadline - time.monotonic())):
                    try:
                        watchdog_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

            watchdog = threading.Thread(target=expire, daemon=True)
            watchdog.start()
            try:
                if self.tls is not None:
                    try:
                        request = self.tls.wrap_socket(request, server_side=True)
                    except OSError:
                        self.shutdown_request(request)
                        return
                super().process_request_thread(request, address)
            finally:
                finished.set()
                watchdog.join()

    def handle_error(self, request, client_address):
        # The wire client observes the transport failure. Untrusted payloads and
        # credentials are deliberately excluded from process logs.
        pass
