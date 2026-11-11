"""Offline transport contracts; parent admission required before running.

All DNS, TCP, TLS, clocks and resolver threads below are synthetic. The real
stdlib HTTP parser reads fake socket bytes. No SDK or product package initializer
is loaded. Missing new private APIs are integration errors, not vulnerability
evidence. Stable-entry baseline cases do not require those new classes.
"""

from contextlib import ExitStack
import hashlib
import http.client
import io
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import sys
import threading
import time
import types
import unittest
from unittest import mock
import urllib.request


SOURCE = Path(__file__).with_name("_verify.py")
PUBLIC = "93.184.216.34"
PUBLIC6 = "2606:4700:4700::1111"
HOST = "origin.example.invalid"


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeEvent:
    def __init__(self, clock):
        self.clock, self.flag = clock, False

    def set(self):
        self.flag = True

    def clear(self):
        self.flag = False

    def is_set(self):
        return self.flag

    def wait(self, timeout=None):
        if not self.flag:
            if timeout is None:
                raise AssertionError("fixture forbids unbounded waits")
            self.clock.advance(max(0, timeout))
        return self.flag


class FakeThread:
    def __init__(self, net, target=None, args=(), kwargs=None, daemon=None, name=None, **unused):
        self.net, self.target = net, target
        self.args, self.kwargs = args, kwargs or {}
        self.daemon, self.name = daemon, name
        self.started = self.done = False
        net.threads.append(self)

    def start(self):
        self.started = True
        if not self.net.hold_dns:
            self.finish()

    def finish(self):
        if self.started and not self.done:
            try:
                self.target(*self.args, **self.kwargs)
            finally:
                self.done = True

    def is_alive(self):
        return self.started and not self.done

    def join(self, timeout=None):
        if self.is_alive():
            if timeout is None:
                raise AssertionError("fixture forbids unbounded thread joins")
            self.net.clock.advance(max(0, timeout))


class SocketReader(io.RawIOBase):
    def __init__(self, sock):
        super().__init__()
        self.sock = sock

    def readable(self):
        return True

    def readinto(self, buffer):
        return self.sock.recv_into(buffer)

    def close(self):
        if not self.closed:
            try:
                super().close()
            finally:
                self.sock._readers -= 1
                if self.sock._closing and not self.sock._readers:
                    self.sock.closed = True


class FakeSocket:
    _offline_fixture_socket = True

    def __init__(self, net, family=socket.AF_INET, *args, **kwargs):
        self.net, self.family = net, family
        self.timeout = None
        self.closed = False
        self.close_calls = 0
        self._sock = self  # Also permits the parent's marker check on the legacy baseline fake.
        self._readers = 0
        self._closing = False
        self.header_left = 0
        self.address = None
        self.incoming = bytearray()
        self.sent = bytearray()
        net.sockets.append(self)

    def settimeout(self, value):
        self.timeout = value
        self.net.timeouts.append(value)

    def gettimeout(self):
        return self.timeout

    def setsockopt(self, *args):
        pass

    def spend(self, seconds):
        if self.timeout is not None and seconds > self.timeout:
            self.net.clock.advance(self.timeout)
            raise TimeoutError("synthetic operation timeout")
        self.net.clock.advance(seconds)

    def connect(self, address):
        self.spend(self.net.connect_cost)
        self.address = address
        self.net.connections.append(address)
        if not self.net.responses:
            raise AssertionError("unexpected connection: no fake response remains")
        self.incoming = bytearray(self.net.responses.pop(0))
        self.header_left = self.incoming.find(b"\r\n\r\n") + 4

    def connect_ex(self, address):
        self.connect(address)
        return 0

    def sendall(self, data, *args):
        self.spend(self.net.send_cost)
        self.sent.extend(data)

    def send(self, data, *args):
        self.sendall(data, *args)
        return len(data)

    def recv_into(self, buffer, nbytes=0, flags=0):
        if self.closed:
            raise OSError("synthetic socket already closed")
        if not self.incoming:
            return 0
        cost = self.net.recv_cost if self.header_left or self.net.body_cost is None else self.net.body_cost
        self.spend(cost)
        count = min(len(buffer), nbytes or len(buffer), len(self.incoming), self.net.chunk)
        buffer[:count] = self.incoming[:count]
        del self.incoming[:count]
        self.header_left = max(0, self.header_left - count)
        self.net.received += count
        return count

    def recv(self, size, flags=0):
        buffer = bytearray(size)
        count = self.recv_into(buffer, size, flags)
        return bytes(buffer[:count])

    def makefile(self, mode="rb", buffering=None, *args, **kwargs):
        if mode not in ("r", "rb"):
            raise AssertionError("unexpected fixture socket file mode")
        self._readers += 1
        return io.BufferedReader(SocketReader(self))

    def getpeername(self):
        return self.address

    def shutdown(self, *args):
        pass

    def close(self):
        self.close_calls += 1
        self._closing = True
        if not self._readers:
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FakeTLSContext:
    def __init__(self, net, protocol=ssl.PROTOCOL_TLS_CLIENT, *args, **kwargs):
        self.net, self.protocol = net, protocol
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED
        self.verify_flags = 0
        self.options = 0
        self.post_handshake_auth = False
        self.loaded_defaults = False
        self.alpn = None
        net.contexts.append(self)

    def load_default_certs(self, *args, **kwargs):
        self.loaded_defaults = True

    def load_verify_locations(self, *args, **kwargs):
        raise AssertionError("fixture forbids ambient CA file access")

    def set_alpn_protocols(self, protocols):
        self.alpn = protocols

    def wrap_socket(self, sock, *, server_hostname=None, **kwargs):
        sock.spend(self.net.tls_cost)
        self.net.sni.append(server_hostname)
        self.net.tls_policy.append((self.check_hostname, self.verify_mode))
        return sock


class FakeNetwork:
    def __init__(self):
        self.clock = FakeClock()
        self.responses = []
        self.sockets, self.connections, self.contexts, self.threads = [], [], [], []
        self.dns_calls, self.sni, self.tls_policy, self.timeouts = [], [], [], []
        self.answers = [PUBLIC]
        self.rebind_after_first = False
        self.hold_dns = False
        self.dns_cost = self.connect_cost = self.tls_cost = 0.0
        self.recv_cost = self.send_cost = 0.0
        self.body_cost = None
        self.chunk = 8192
        self.received = 0

    def getaddrinfo(self, host, port, *args, **kwargs):
        self.dns_calls.append((host, port))
        self.clock.advance(self.dns_cost)
        try:
            addresses = [str(ipaddress.ip_address(host))]
        except ValueError:
            addresses = ["127.0.0.1"] if self.rebind_after_first and len(self.dns_calls) > 1 else self.answers
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM,
             socket.IPPROTO_TCP, "", (ip, port, 0, 0) if ":" in ip else (ip, port))
            for ip in addresses
        ]

    def response(self, body=b"<p>ALPHA &amp; Beta</p>", status=200, headers=()):
        lines = [f"HTTP/1.1 {status} Fixture", f"Content-Length: {len(body)}", "Connection: close"]
        lines.extend(f"{key}: {value}" for key, value in headers)
        self.responses.append(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)


class TransportBoundaries(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.net = FakeNetwork()
        # Patch OS-effect boundaries BEFORE source definitions are loaded.
        self.stack.enter_context(mock.patch.object(socket, "socket", side_effect=lambda *a, **k: FakeSocket(self.net, *a, **k)))
        self.stack.enter_context(mock.patch.object(socket, "getaddrinfo", side_effect=self.net.getaddrinfo))
        self.stack.enter_context(mock.patch.object(ssl, "SSLContext", side_effect=lambda *a, **k: FakeTLSContext(self.net, *a, **k)))
        self.stack.enter_context(mock.patch.object(threading, "Thread", side_effect=lambda *a, **k: FakeThread(self.net, *a, **k)))
        self.stack.enter_context(mock.patch.object(threading, "Event", side_effect=lambda: FakeEvent(self.net.clock)))
        self.stack.enter_context(mock.patch.object(time, "monotonic", side_effect=self.net.clock))
        self.stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
        self.proxy_lookup = self.stack.enter_context(mock.patch.object(urllib.request, "getproxies", return_value={}))
        self.stack.enter_context(mock.patch.object(urllib.request, "proxy_bypass", return_value=False))
        self.opener = self.stack.enter_context(mock.patch.object(urllib.request, "build_opener", wraps=urllib.request.build_opener))
        with SOURCE.open("rb") as stream:
            source = stream.read(262145)
        self.assertLessEqual(len(source), 262144)
        self.source_sha256 = hashlib.sha256(source).hexdigest()
        name = "_transport_fixture_" + str(id(self))
        self.v = types.ModuleType(name)
        self.v.__file__ = str(SOURCE)
        sys.modules[name] = self.v
        self.addCleanup(sys.modules.pop, name, None)
        exec(compile(source, str(SOURCE), "exec"), self.v.__dict__)
        self.addCleanup(self.finish_fake_threads)

    def finish_fake_threads(self):
        for thread in self.net.threads:
            thread.finish()

    def fetch(self, url="http://" + HOST + "/docs"):
        return self.v._fetch_text(url)

    def assert_numeric_public_connections(self):
        self.assertTrue(self.net.connections, "real transport path must reach fake TCP connect")
        for address in self.net.connections:
            self.assertTrue(ipaddress.ip_address(address[0]).is_global)

    def test_stable_no_ambient_opener_or_proxy_lookup(self):
        self.net.response()
        self.assertEqual(self.fetch(), " alpha & beta ")
        self.opener.assert_not_called()
        self.proxy_lookup.assert_not_called()

    def test_stable_one_dns_admission_binds_numeric_connect_despite_rebinding(self):
        self.net.rebind_after_first = True
        self.net.response()
        self.assertEqual(self.fetch(), " alpha & beta ")
        self.assertEqual(self.net.dns_calls, [(HOST, 80)])
        self.assert_numeric_public_connections()
        self.assertEqual(self.net.connections[0][0], PUBLIC)

    def test_stable_cumulative_header_and_body_budget(self):
        self.net.chunk = 1
        self.net.recv_cost = 4.0
        self.net.response(b"body")
        with self.assertRaises(TimeoutError):
            self.fetch("http://" + PUBLIC + "/slow")
        self.assertLessEqual(self.net.clock(), self.v.FETCH_TIMEOUT_S + 0.001)

    def test_stable_body_drip_cannot_reset_aggregate_deadline(self):
        self.net.chunk = 1
        self.net.body_cost = 4.0
        self.net.response(b"drip")
        with self.assertRaises(TimeoutError):
            self.fetch("http://" + PUBLIC + "/slow-body")
        self.assertLessEqual(self.net.clock(), self.v.FETCH_TIMEOUT_S + 0.001)

    def test_ambient_proxy_environment_cannot_change_numeric_destination(self):
        self.net.response()
        self.proxy_lookup.return_value = {"http": "http://127.0.0.1:8888"}
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:8888", "http_proxy": "http://127.0.0.1:8888"}):
            self.assertEqual(self.fetch(), " alpha & beta ")
        self.opener.assert_not_called()
        self.proxy_lookup.assert_not_called()
        self.assertEqual(self.net.connections, [(PUBLIC, 80)])

    def test_public_literal_avoids_dns_and_preserves_validator_return(self):
        self.assertIsNone(self.v._validate_fetch_url("http://" + PUBLIC + "/docs"))
        self.assertEqual(self.net.dns_calls, [])
        self.net.response()
        self.assertEqual(self.fetch("http://" + PUBLIC + "/docs"), " alpha & beta ")
        self.assertEqual(self.net.dns_calls, [])

    def test_http_origin_host_and_path_are_preserved(self):
        self.net.response()
        self.fetch("http://" + HOST + ":8080/a?b=1#local")
        sent = bytes(self.net.sockets[0].sent).lower()
        self.assertIn(b"get /a?b=1 http/1.1\r\n", sent)
        self.assertIn(("host: " + HOST + ":8080\r\n").encode(), sent)
        self.assertNotIn(b"#local", sent)
        self.assert_numeric_public_connections()

    def test_https_numeric_tcp_retains_original_sni_and_certificate_policy(self):
        self.net.response()
        self.assertEqual(self.fetch("https://" + HOST + "/docs"), " alpha & beta ")
        self.assert_numeric_public_connections()
        self.assertEqual(self.net.sni, [HOST])
        self.assertEqual(self.net.tls_policy, [(True, ssl.CERT_REQUIRED)])
        self.assertTrue(self.net.contexts[0].loaded_defaults)
        self.assertEqual(self.net.contexts[0].alpn, ["http/1.1"])
        self.assertEqual(self.net.contexts[0].protocol, ssl.PROTOCOL_TLS_CLIENT)

    def test_public_ipv6_literal_connect_and_bracketed_host(self):
        self.net.response()
        self.assertEqual(self.fetch("http://[" + PUBLIC6 + "]:8080/docs"), " alpha & beta ")
        self.assertEqual(self.net.dns_calls, [])
        self.assertEqual(self.net.connections[0][:2], (PUBLIC6, 8080))
        self.assertEqual(self.net.sockets[0].family, socket.AF_INET6)
        self.assertIn(("Host: [" + PUBLIC6 + "]:8080\r\n").lower().encode(), bytes(self.net.sockets[0].sent).lower())

    def test_mixed_public_private_dns_answers_refuse_before_connect(self):
        self.net.answers = [PUBLIC, "10.0.0.1"]
        with self.assertRaises(ValueError):
            self.fetch()
        self.assertEqual(self.net.connections, [])

    def test_relative_redirect_is_revalidated_and_followed(self):
        self.net.response(b"", 302, [("Location", "/next")])
        self.net.response(b"<b>FINAL</b>")
        self.assertEqual(self.fetch(), " final ")
        self.assertEqual(len(self.net.connections), 2)
        self.assert_numeric_public_connections()
        self.assertIn(b"GET /next HTTP/1.1", bytes(self.net.sockets[1].sent))

    def test_private_redirect_refuses_without_second_connection(self):
        self.net.response(b"", 302, [("Location", "http://127.0.0.1/private")])
        with self.assertRaises(ValueError):
            self.fetch()
        self.assertEqual(len(self.net.connections), 1)

    def test_redirect_to_hostname_rejects_any_private_answer(self):
        self.net.response(b"", 302, [("Location", "http://redirect.example.invalid/")])
        original = self.net.getaddrinfo

        def resolve(host, port, *args, **kwargs):
            if host == "redirect.example.invalid":
                self.net.answers = ["192.168.1.1"]
            return original(host, port, *args, **kwargs)

        with mock.patch.object(socket, "getaddrinfo", side_effect=resolve):
            with self.assertRaises(ValueError):
                self.fetch()
        self.assertEqual(len(self.net.connections), 1)

    def test_redirect_chain_has_finite_limit(self):
        for index in range(30):
            self.net.response(b"", 302, [("Location", "/hop" + str(index))])
        with self.assertRaises((ValueError, OSError)):
            self.fetch()
        self.assertLess(len(self.net.connections), 30)

    def test_redirects_share_original_deadline(self):
        self.net.connect_cost = 4.0
        self.net.response(b"", 302, [("Location", "/one")])
        self.net.response(b"", 302, [("Location", "/two")])
        self.net.response(b"done")
        with self.assertRaises(TimeoutError):
            self.fetch("http://" + PUBLIC + "/start")
        self.assertLessEqual(self.net.clock(), self.v.FETCH_TIMEOUT_S + 0.001)

    def test_chunked_http_body_uses_real_parser_and_closes_fake_socket(self):
        self.net.responses.append(
            b"HTTP/1.1 200 Fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            b"5\r\nHELLO\r\n0\r\n\r\n"
        )
        self.assertEqual(self.fetch(), "hello")
        self.assertTrue(all(sock.closed for sock in self.net.sockets))

    def test_body_at_limit_is_preserved(self):
        self.net.response(b"x" * self.v.MAX_FETCH_BYTES)
        self.assertEqual(len(self.fetch()), self.v.MAX_FETCH_BYTES)

    def test_body_one_byte_over_limit_is_rejected_not_truncated(self):
        self.net.response(b"x" * (self.v.MAX_FETCH_BYTES + 1))
        with self.assertRaises(ValueError):
            self.fetch()

    def test_shared_budget_includes_dns_connect_and_tls(self):
        self.net.dns_cost = 4.0
        self.net.connect_cost = 4.0
        self.net.tls_cost = 4.0
        self.net.response()
        with self.assertRaises(TimeoutError):
            self.fetch("https://" + HOST + "/docs")
        self.assertLessEqual(self.net.clock(), self.v.FETCH_TIMEOUT_S + 0.001)

    def test_deadline_reader_rechecks_before_each_receive(self):
        raw = FakeSocket(self.net)
        raw.incoming = bytearray(b"ab")
        wrapped = self.v._DeadlineSocket(raw, self.v._Deadline(2))
        with wrapped.makefile("rb") as stream:
            self.net.chunk = 1
            self.assertEqual(stream.read(1), b"a")
            self.net.clock.advance(3)
            with self.assertRaises(TimeoutError):
                stream.read(1)
        self.assertEqual(raw.incoming, bytearray(b"b"))

    def test_deadline_send_refuses_expired_without_sending(self):
        raw = FakeSocket(self.net)
        wrapped = self.v._DeadlineSocket(raw, self.v._Deadline(1))
        self.net.clock.advance(2)
        with self.assertRaises(TimeoutError):
            wrapped.sendall(b"must-not-send")
        self.assertEqual(raw.sent, b"")

    def test_deadline_makefile_owns_raw_socket_until_reader_closes_once(self):
        raw = FakeSocket(self.net)
        wrapped = self.v._DeadlineSocket(raw, self.v._Deadline(2))
        stream = wrapped.makefile("rb")
        self.addCleanup(stream.close)
        wrapped.close()
        wrapped.close()
        self.assertFalse(raw.closed)
        self.assertEqual(raw.close_calls, 0)
        stream.close()
        self.assertTrue(raw.closed)
        self.assertEqual(raw.close_calls, 1)
        wrapped.close()
        stream.close()
        self.assertEqual(raw.close_calls, 1)

    def test_timed_out_dns_keeps_four_slots_until_workers_finish(self):
        self.net.hold_dns = True
        for _ in range(4):
            with self.assertRaises(TimeoutError):
                self.v._bounded_getaddrinfo(HOST, 80, self.v._Deadline(1))
        self.assertEqual(sum(t.is_alive() for t in self.net.threads), 4)
        with self.assertRaises((TimeoutError, ValueError)):
            self.v._bounded_getaddrinfo(HOST, 80, self.v._Deadline(1))
        self.assertEqual(len(self.net.threads), 4)
        self.assertTrue(all(t.daemon for t in self.net.threads))
        self.net.threads[0].finish()
        self.net.hold_dns = False
        self.assertTrue(self.v._bounded_getaddrinfo(HOST, 80, self.v._Deadline(1)))

    def test_verify_claim_default_reuses_admitted_dns_target_once(self):
        self.net.rebind_after_first = True
        self.net.response(b"alpha payment proposal")
        result = self.v.verify_claim("Alpha payment proposal", "http://" + HOST + "/docs")
        self.assertIs(result["verified"], False)
        self.assertEqual(result["level"], "PROPOSED")
        self.assertEqual(self.net.dns_calls, [(HOST, 80)])
        self.assert_numeric_public_connections()

    def test_injected_fetcher_still_requires_admission_first(self):
        fetcher = mock.Mock(return_value="alpha payment proposal")
        result = self.v.verify_claim("Alpha payment proposal", "http://127.0.0.1/", fetch_fn=fetcher)
        self.assertEqual(result["level"], "UNKNOWN")
        fetcher.assert_not_called()
        self.assertEqual(self.net.connections, [])


    def test_partial_tls_send_respects_aggregate_deadline(self):
        class PartialTLS(FakeSocket):
            def send(self, data, *args):
                self.spend(4.0)
                self.sent.extend(data[:1])
                return 1

            def sendall(self, data, *args):
                offset = 0
                while offset < len(data):
                    offset += self.send(data[offset:])

        raw = PartialTLS(self.net)
        facade = self.v._DeadlineSocket(raw, self.v._Deadline(10))
        with self.assertRaises(TimeoutError):
            facade.sendall(b"abcd")
        self.assertLessEqual(self.net.clock(), 10.001)
        self.assertLessEqual(len(raw.sent), 2)

    def test_zero_progress_send_raises_connection_error(self):
        class ZeroProgress(FakeSocket):
            def send(self, data, *args):
                return 0

            def sendall(self, data, *args):
                return None

        raw = ZeroProgress(self.net)
        facade = self.v._DeadlineSocket(raw, self.v._Deadline(10))
        with self.assertRaises(ConnectionError):
            facade.sendall(b"pending")

    def test_truncated_declared_body_keeps_default_claim_unknown(self):
        self.net.responses.append(
            b"HTTP/1.1 200 Fixture\r\nContent-Length: 100\r\n"
            b"Connection: close\r\n\r\nalpha payment proposal"
        )
        result = self.v.verify_claim(
            "Alpha payment proposal", "http://" + PUBLIC + "/truncated"
        )
        self.assertEqual(result["level"], "UNKNOWN")
        self.assertIs(result["verified"], False)

    def test_resolver_start_failure_is_unknown_and_releases_all_slots(self):
        with mock.patch.object(
            FakeThread, "start", side_effect=RuntimeError("synthetic resolver start failure")
        ):
            for _ in range(4):
                result = self.v.verify_claim(
                    "Alpha payment proposal", "http://" + HOST + "/dns"
                )
                self.assertEqual(result["level"], "UNKNOWN")
                self.assertIs(result["verified"], False)
        acquired = []
        try:
            for _ in range(4):
                available = self.v._DNS_SLOTS.acquire(blocking=False)
                if available:
                    acquired.append(True)
                self.assertTrue(available, "resolver startup leaked a DNS slot")
        finally:
            for _ in acquired:
                self.v._DNS_SLOTS.release()

    def assert_fast_html_fetch(self, body, expected, label):
        self.assertEqual(len(body), self.v.MAX_FETCH_BYTES)
        with mock.patch.object(self.v, "_fetch_bytes", return_value=body):
            started = time.perf_counter()
            result = self.fetch()
            elapsed = time.perf_counter() - started
        self.assertEqual(result, expected)
        self.assertLess(elapsed, 1.0, "2 MiB HTML preprocessing exceeded one second")
        print(f"HTML_STRIP_TIMING={label} bytes={len(body)} seconds={elapsed:.6f}")

    def test_html_two_mib_unclosed_script(self):
        body = (b"<script" * (self.v.MAX_FETCH_BYTES // 7 + 1))[:self.v.MAX_FETCH_BYTES]
        self.assert_fast_html_fetch(body, " ", "unclosed-script")

    def test_html_two_mib_unclosed_style(self):
        body = (b"<StYlE" * (self.v.MAX_FETCH_BYTES // 6 + 1))[:self.v.MAX_FETCH_BYTES]
        self.assert_fast_html_fetch(body, " ", "unclosed-style")

    def test_html_two_mib_unclosed_generic_tags(self):
        body = b"<" * self.v.MAX_FETCH_BYTES
        self.assert_fast_html_fetch(body, body.decode(), "unclosed-generic")

    def test_html_two_mib_many_closed_raw_elements(self):
        for tag in ("script", "style"):
            with self.subTest(tag=tag):
                element = f"<{tag}>ignored</{tag}>".encode()
                count, tail = divmod(self.v.MAX_FETCH_BYTES, len(element))
                body = element * count + b"x" * tail
                self.assert_fast_html_fetch(body, " " * count + "x" * tail, "closed-" + tag)

    def test_html_closed_blocks_case_multiline_and_entities(self):
        body = (b"Before<ScRiPt type='text/plain'>\nsecret <script> nested\n</sCrIpT>"
                b"Middle<STYLE media='all'>\n.secret{}\n</style>After &amp; END")
        with mock.patch.object(self.v, "_fetch_bytes", return_value=body):
            self.assertEqual(self.fetch(), "before middle after & end")

    def test_html_unterminated_raw_blocks_drop_remaining(self):
        for body in (b"Visible<script ignored <script hidden", b"Visible<STYLE>hidden",
                     b"Visible<script", b"Visible<styLE"):
            with self.subTest(body=body), mock.patch.object(self.v, "_fetch_bytes", return_value=body):
                self.assertEqual(self.fetch(), "visible ")

    def test_html_generic_tags_empty_and_unclosed(self):
        body = b"<>Alpha<p class='q'>Beta</p>tail<broken"
        with mock.patch.object(self.v, "_fetch_bytes", return_value=body):
            self.assertEqual(self.fetch(), "<>alpha beta tail<broken")

    def test_html_expired_budget_prevents_decode(self):
        decoded = []

        class ObservableBytes(bytes):
            def decode(self, *args, **kwargs):
                decoded.append(True)
                return super().decode(*args, **kwargs)

        def expired_fetch(*args, **kwargs):
            self.net.clock.advance(self.v.FETCH_TIMEOUT_S + 1)
            return ObservableBytes(b"<script>ignored</script>")

        with mock.patch.object(self.v, "_fetch_bytes", side_effect=expired_fetch):
            with self.assertRaises(TimeoutError):
                self.fetch()
        self.assertEqual(decoded, [], "expired fetch must refuse before HTML preprocessing")

    def test_html_budget_expiring_during_decode_still_refuses(self):
        clock = self.net.clock

        class SlowDecode(bytes):
            def decode(self, *args, **kwargs):
                clock.advance(11)
                return super().decode(*args, **kwargs)

        with mock.patch.object(self.v, "_fetch_bytes", return_value=SlowDecode(b"<p>alpha</p>")):
            with self.assertRaises(TimeoutError):
                self.fetch()

    def test_html_ascii_tag_folding_keeps_unicode_text_positions(self):
        body = "İ ſ K before<ScRiPt>hidden</SCRIPT>after<STYLE>hidden</style>Ω".encode()
        with mock.patch.object(self.v, "_fetch_bytes", return_value=body):
            self.assertEqual(self.fetch(), "i\u0307 ſ k before after ω")


if __name__ == "__main__":
    unittest.main(verbosity=2)
