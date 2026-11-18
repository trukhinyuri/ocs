#!/usr/bin/env python3
"""Transport a Git service stream through a private, socket-activated native receiver."""

import argparse
import os
import re
import socket
import sys
import threading
from pathlib import Path

INSTANCE = re.compile(r"[a-z][a-z0-9-]{0,22}")
SERVICES = ("git-receive-pack", "git-upload-pack")
SOCKET_ROOT = Path("/run/ocs-safe-push")


def forward(path, service, *, announce_connect=False):
    """Send the server selector and switch both ends to a byte-transparent stream."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.connect(os.fspath(path))
        conn.sendall((service + "\n").encode("ascii"))
        if announce_connect:
            # Git consumes this one LF before interpreting the server's packet stream.
            os.write(1, b"\n")

        def send():
            try:
                while block := os.read(0, 65536):
                    conn.sendall(block)
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                # The peer can legitimately finish and close while stdin is closing.
                return

        worker = threading.Thread(target=send, daemon=True)
        worker.start()
        while block := conn.recv(65536):
            sys.stdout.buffer.write(block)
            sys.stdout.buffer.flush()


def command_line():
    """Leave all bytes after LF on the same descriptor for the transparent Git protocol."""
    line = bytearray()
    while len(line) < 80:
        ch = os.read(0, 1)
        if ch == b"\n":
            return bytes(line)
        if not ch:
            if line:
                raise ValueError("incomplete Git helper command")
            return None
        line.extend(ch)
    raise ValueError("oversized Git helper command")


def git_helper(instance, socket_root=SOCKET_ROOT):
    if not INSTANCE.fullmatch(instance):
        raise ValueError("invalid receiver instance")
    if command_line() != b"capabilities":
        raise ValueError("expected Git helper capabilities")
    os.write(1, b"connect\n\n")
    command = command_line()
    if not command:
        return
    for service in SERVICES:
        if command == ("connect " + service).encode("ascii"):
            forward(socket_root / (instance + ".sock"), service, announce_connect=True)
            return
    raise ValueError("unsupported Git helper service")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--git-helper":
        git_helper(sys.argv[2])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket")
    parser.add_argument("service", choices=SERVICES)
    args = parser.parse_args()
    forward(args.socket, args.service)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print("OCS Git transport: " + str(exc), file=sys.stderr)
        sys.exit(1)
