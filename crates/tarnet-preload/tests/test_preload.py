"""Run after cargo build --release: python3 crates/tarnet-preload/tests/test_preload.py.

Tests real dynamic injection and SOCKS wire requests, plus the CLI/daemon path.
Requires localhost sockets; uses only the Python standard library and a C compiler.
"""
import concurrent.futures
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
MACOS = sys.platform == "darwin"
LIB_NAME = "libtarnet_preload." + ("dylib" if MACOS else "so")
PRELOAD_ENV = "DYLD_INSERT_LIBRARIES" if MACOS else "LD_PRELOAD"


def exact(connection, size):
    data = b""
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise AssertionError("unexpected EOF")
        data += part
    return data


class PreloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="tarify-", dir="/tmp")
        cls.client = Path(cls.temp.name) / "client"
        cls.library = Path(cls.temp.name) / LIB_NAME
        source = ROOT / "crates/tarnet-preload"
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-o", str(cls.client),
                        str(source / "tests/client.c")], check=True)
        flags = ["-dynamiclib"] if MACOS else ["-shared", "-D_GNU_SOURCE", "-ldl"]
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-fPIC", *flags,
                        "-o", str(cls.library), str(source / "src/preload.c"),
                        "-lpthread"], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_client(self, mode, host, port, env, prefix=()):
        result = subprocess.run([*map(str, prefix), str(self.client), mode, host, str(port)],
                                env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def check_socks(self, mode, identity=None):
        with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor() as pool:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(10)
            host = "198.51.100.7" if mode == "ipv4" else "tarify-test.invalid"

            def serve():
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(10)
                    method = 2 if identity else 0
                    self.assertEqual(exact(connection, 3), bytes([5, 1, method]))
                    connection.sendall(bytes([5, method]))
                    if identity:
                        self.assertEqual(exact(connection, 2), bytes([1, len(identity)]))
                        self.assertEqual(exact(connection, len(identity)), identity.encode())
                        self.assertEqual(exact(connection, 1), b"\0")
                        connection.sendall(b"\x01\0")
                    header = exact(connection, 4)
                    self.assertEqual(header[:3], b"\x05\x01\0")
                    if mode == "ipv4":
                        self.assertEqual(header[3], 1)
                        self.assertEqual(exact(connection, 4), socket.inet_aton(host))
                    else:
                        self.assertEqual(header[3], 3)
                        size = exact(connection, 1)[0]
                        self.assertEqual(exact(connection, size).decode(), host)
                    self.assertEqual(exact(connection, 2), (8080).to_bytes(2, "big"))
                    connection.sendall(b"\x05\0\0\x01" + b"\0" * 6)
                    connection.sendall(exact(connection, 4))

            task = pool.submit(serve)
            env = dict(os.environ, **{PRELOAD_ENV: str(self.library),
                       "TARIFY_PROXY_ADDR": "127.0.0.1:%d" % listener.getsockname()[1]})
            env.pop("TARIFY_IDENTITY", None)
            if identity:
                env["TARIFY_IDENTITY"] = identity
            self.run_client(mode, host, 8080, env)
            task.result(timeout=10)

    def test_hostname(self):
        self.check_socks("hostname")

    def test_legacy_hostname(self):
        self.check_socks("legacy")

    def test_ipv4(self):
        self.check_socks("ipv4")

    def test_nonblocking_flags_restored(self):
        self.check_socks("nonblocking")

    def test_identity_auth(self):
        self.check_socks("hostname", "work")

    def test_without_proxy_uses_libc(self):
        # Exercises original resolution/connect/free functions, including dyld's
        # exemption for references from the interposer's own image.
        env = dict(os.environ, **{PRELOAD_ENV: str(self.library)})
        env.pop("TARIFY_PROXY_ADDR", None)
        env.pop("TARIFY_IDENTITY", None)
        for mode in ("hostname", "legacy"):
            with self.subTest(mode=mode), socket.socket() as server, concurrent.futures.ThreadPoolExecutor() as pool:
                server.bind(("127.0.0.1", 0))
                server.listen()
                server.settimeout(10)

                def echo():
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(10)
                        connection.sendall(exact(connection, 4))

                task = pool.submit(echo)
                self.run_client(mode, "localhost", server.getsockname()[1], env)
                task.result(timeout=10)

    def test_udp_passes_through(self):
        with socket.socket(type=socket.SOCK_DGRAM) as server, concurrent.futures.ThreadPoolExecutor() as pool:
            server.bind(("127.0.0.1", 0))
            server.settimeout(10)

            def echo():
                data, address = server.recvfrom(32)
                server.sendto(data, address)

            task = pool.submit(echo)
            env = dict(os.environ, **{PRELOAD_ENV: str(self.library),
                                      "TARIFY_PROXY_ADDR": "127.0.0.1:1"})
            self.run_client("udp", "127.0.0.1", server.getsockname()[1], env)
            task.result(timeout=10)

    def test_cli_daemon(self):
        daemon = ROOT / "target/release/tarnetd"
        cli = ROOT / "target/release/tarnet"
        with tempfile.TemporaryDirectory(prefix="tarify-daemon-", dir="/tmp") as directory:
            # The daemon currently reports configured SOCKS addresses over IPC,
            # so reserve an ephemeral port rather than advertising port zero.
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                socks_port = reservation.getsockname()[1]
            log = tempfile.TemporaryFile(mode="w+")
            process = subprocess.Popen([str(daemon), "--data-dir", directory,
                "--config-dir", directory, "--listen", "127.0.0.1:0", "--socks",
                "127.0.0.1:%d" % socks_port, "--socks-allow-clearnet", "--no-mdns", "--no-webrtc",
                "--no-ws"], stdout=log, stderr=log,
                env=dict(os.environ, RUST_LOG="info,tarnet_socks=debug"))
            try:
                for _ in range(100):
                    if (Path(directory) / "sock").exists():
                        break
                    self.assertIsNone(process.poll(), "daemon exited before creating IPC socket")
                    time.sleep(0.05)
                self.assertTrue((Path(directory) / "sock").exists())
                with socket.socket() as server, concurrent.futures.ThreadPoolExecutor() as pool:
                    server.bind(("127.0.0.1", 0))
                    server.listen()
                    server.settimeout(10)

                    def echo():
                        connection, _ = server.accept()
                        with connection:
                            connection.settimeout(10)
                            connection.sendall(exact(connection, 4))

                    task = pool.submit(echo)
                    env = dict(os.environ)
                    env.pop(PRELOAD_ENV, None)
                    self.run_client("ipv4", "127.0.0.1", server.getsockname()[1], env,
                                    [cli, "--data-dir", directory, "tarify", "--identity", "default"])
                    task.result(timeout=10)
                    log.seek(0)
                    self.assertIn("CONNECT request: 127.0.0.1:%d" % server.getsockname()[1],
                                  log.read(), "client bypassed the SOCKS proxy")
            finally:
                process.terminate()
                process.wait(timeout=10)
                log.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
