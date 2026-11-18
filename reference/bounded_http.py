"""HTTP workers with bounded admission, bounded reads and optional per-worker TLS."""

import socket
import ssl
import threading
from http.server import HTTPServer
from socketserver import ThreadingMixIn


class BoundedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, *, workers=4, timeout=5, tls=None):
        if workers < 1 or timeout <= 0:
            raise ValueError("positive admission and time budgets required")
        self.slots = threading.BoundedSemaphore(workers)
        self.request_queue_size = workers
        self.io_timeout = timeout
        self.tls = tls
        super().__init__(address, handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self.io_timeout)
        return request, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
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
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            if self.tls is not None:
                try:
                    request = self.tls.wrap_socket(request, server_side=True)
                except (ssl.SSLError, socket.timeout, OSError):
                    self.shutdown_request(request)
                    return
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # The wire client observes the transport failure. Untrusted payloads and
        # credentials are deliberately excluded from process logs.
        pass
