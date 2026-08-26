#!/usr/bin/env python3
#
# Optional black-box tests for the knc executable.  These tests deliberately
# require Heimdal's kimpersonate and a working local socket stack, so they are
# not part of the default Automake check target.

import argparse
import base64
import hashlib
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest


REALM = "KNC.TEST"
CLIENT_PRINC = "client@%s" % REALM
SERVER_PRINC = "host/127.0.0.1@%s" % REALM
ENCTYPE = "aes256-cts-hmac-sha1-96"
CLIENT_PASSWORD = "knc-exec-client-password"
MASTER_PASSWORD = "knc-exec-master-password"
KNC_TIMEOUT = 20
OUTPUT_LIMIT = 4096


def output_text(data):
    display = data[:OUTPUT_LIMIT]
    text = display.decode("utf-8", "replace")
    if len(data) > OUTPUT_LIMIT:
        text += "\n[truncated to %d of %d bytes]" % (OUTPUT_LIMIT, len(data))
    return text


HELPER = r'''
#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import sys
import time


def payload(size):
    return bytes(((i * 31 + 7) & 0xff) for i in range(size))


def read_all(delay=False):
    chunks = []
    while True:
        data = os.read(0, 8192)
        if not data:
            break
        chunks.append(data)
        if delay:
            time.sleep(0.002)
    return b"".join(chunks)


def read_exact(length):
    chunks = []
    remaining = length
    while remaining > 0:
        data = os.read(0, remaining)
        if not data:
            raise EOFError("short input")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def write_all(data):
    view = memoryview(data)
    while view:
        written = os.write(1, view)
        view = view[written:]


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True)
    os.rename(tmp, path)


def write_bin(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.rename(tmp, path)


def append_json_line(path, obj):
    with open(path, "ab") as f:
        f.write(json.dumps(obj, sort_keys=True).encode("utf-8") + b"\n")


def digest(data):
    return {"len": len(data), "sha256": hashlib.sha256(data).hexdigest()}


scenario = sys.argv[1]
side = sys.argv[2]

if scenario == "env":
    keys = [
        "KNC_MECH",
        "KNC_CREDS",
        "KNC_EXPORT_NAME",
        "KNC_REMOTE_ADDR",
        "KNC_REMOTE_IP",
        "KNC_REMOTE_IP6",
        "KNC_REMOTE_PORT",
        "KNC_VERSION",
    ]
    write_json(side, {k: os.environ.get(k) for k in keys})

elif scenario == "stdin_binary":
    write_bin(side, read_all())

elif scenario == "stdout_binary":
    data = payload(65537)
    write_all(data)
    write_json(side, digest(data))

elif scenario == "request_response":
    req1 = read_exact(5)
    write_all(b"one:" + req1)
    req2 = read_exact(4)
    write_all(b"two:" + req2)
    rest = read_all()
    write_json(side, {"rest": base64.b64encode(rest).decode("ascii")})

elif scenario == "large_request_response":
    first = read_exact(8192)
    response = payload(512 * 1024 + 29)
    write_all(response)
    rest = read_all(delay=True)
    data = first + rest
    write_json(side, {
        "input": digest(data),
        "response": digest(response),
    })

elif scenario == "client_half_close":
    data = read_all()
    status = "not-written"
    try:
        write_all(b"after-eof:" + data)
        status = "written"
    except BrokenPipeError:
        status = "broken-pipe"
    write_json(side, {"input": digest(data), "write_status": status})

elif scenario == "drain_before_eof":
    data = read_all(delay=True)
    write_json(side, digest(data))

elif scenario == "child_output_then_exit":
    write_all(payload(1024 * 1024 + 333))

elif scenario == "stdout_close_keeps_reading":
    append_json_line(side, {"event": "start"})
    os.close(1)
    append_json_line(side, {"event": "stdout_closed"})

    data = read_all()
    result = digest(data)
    result["event"] = "read_done"
    append_json_line(side, result)

elif scenario == "connection_marker":
    data = read_all()
    write_all(b"conn:" + data)
    result = digest(data)
    result["data"] = base64.b64encode(data).decode("ascii")
    append_json_line(side, result)

elif scenario == "stderr_not_tunneled":
    stdout_marker = b"stdout-marker\n"
    stderr_marker = b"stderr-marker\n"
    write_all(stdout_marker)
    os.write(2, stderr_marker)
    write_json(side, {
        "stdout": stdout_marker.decode("ascii"),
        "stderr": stderr_marker.decode("ascii"),
    })

else:
    raise SystemExit("unknown scenario: %s" % scenario)
'''


def deterministic_payload(size):
    return bytes(((i * 31 + 7) & 0xff) for i in range(size))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class MissingTool(RuntimeError):
    pass


class KNCExecTests(unittest.TestCase):
    knc_path = os.path.join("bin", "knc")
    client_knc_path = None
    server_knc_path = None

    @classmethod
    def setUpClass(cls):
        cls.knc = os.path.abspath(cls.knc_path)
        cls.client_knc = os.path.abspath(cls.client_knc_path or cls.knc_path)
        cls.server_knc = os.path.abspath(cls.server_knc_path or cls.knc_path)
        cls.tmp = tempfile.TemporaryDirectory(prefix="knc-exec-tests.")
        cls.tmpdir = cls.tmp.name
        cls.helper = os.path.join(cls.tmpdir, "knc_exec_helper.py")
        cls.keytab = os.path.join(cls.tmpdir, "server.keytab")
        cls.ccache = os.path.join(cls.tmpdir, "client.ccache")
        cls.krb5_conf = os.path.join(cls.tmpdir, "krb5.conf")
        cls.kdc_conf = os.path.join(cls.tmpdir, "kdc.conf")
        cls.kdc = None

        if not os.path.exists(cls.client_knc):
            raise RuntimeError(
                "client knc executable not found: %s" % cls.client_knc)
        if not os.path.exists(cls.server_knc):
            raise RuntimeError(
                "server knc executable not found: %s" % cls.server_knc)

        cls.ktutil = shutil.which("ktutil")
        cls.kimpersonate = shutil.which("kimpersonate")
        use_kimpersonate = cls.ktutil is not None and cls.kimpersonate is not None

        if use_kimpersonate:
            kdc_port = None
        else:
            cls.kdb5_util = shutil.which("kdb5_util")
            cls.kadmin_local = shutil.which("kadmin.local")
            cls.krb5kdc = shutil.which("krb5kdc")
            cls.kinit = shutil.which("kinit")
            missing = [
                name for name, path in (
                    ("kdb5_util", cls.kdb5_util),
                    ("kadmin.local", cls.kadmin_local),
                    ("krb5kdc", cls.krb5kdc),
                    ("kinit", cls.kinit),
                ) if path is None
            ]
            if missing:
                raise MissingTool(
                    "kimpersonate or a local MIT KDC (%s)" %
                    ", ".join(missing)
                )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                kdc_port = sock.getsockname()[1]

        with open(cls.helper, "w", encoding="utf-8") as f:
            f.write(textwrap.dedent(HELPER))
        os.chmod(cls.helper, 0o755)

        with open(cls.krb5_conf, "w", encoding="utf-8") as f:
            config = textwrap.dedent("""\
                [libdefaults]
                    default_realm = {realm}
                    dns_lookup_kdc = false
                    dns_lookup_realm = false
                    rdns = false
                    dns_canonicalize_hostname = false
                    ticket_lifetime = 1h
            """.format(realm=REALM))
            if kdc_port is not None:
                config += textwrap.dedent("""\

                    [realms]
                        {realm} = {{
                            kdc = 127.0.0.1:{port}
                        }}
                """.format(realm=REALM, port=kdc_port))
            f.write(config)

        if use_kimpersonate:
            cls.run_checked([
                cls.ktutil, "-k", cls.keytab, "add",
                "--principal=%s" % SERVER_PRINC,
                "--kvno=1",
                "--enctype=%s" % ENCTYPE,
                "--password=knc-exec-test-password",
            ])
            cls.run_checked([
                cls.kimpersonate,
                "--krb5",
                "--client=%s" % CLIENT_PRINC,
                "--server=%s" % SERVER_PRINC,
                "--keytab=%s" % cls.keytab,
                "--ccache=FILE:%s" % cls.ccache,
                "--enc-type=%s" % ENCTYPE,
                "--session-enc-type=%s" % ENCTYPE,
            ])
        else:
            cls.start_local_kdc(kdc_port)

    @classmethod
    def start_local_kdc(cls, port):
        database = os.path.join(cls.tmpdir, "principal")
        with open(cls.kdc_conf, "w", encoding="utf-8") as f:
            f.write(textwrap.dedent("""\
                [kdcdefaults]
                    kdc_ports = {port}
                    kdc_tcp_ports = {port}

                [realms]
                    {realm} = {{
                        database_name = {database}
                        key_stash_file = {stash}
                        acl_file = {acl}
                    }}
            """.format(
                port=port,
                realm=REALM,
                database=database,
                stash=os.path.join(cls.tmpdir, ".k5.%s" % REALM),
                acl=os.path.join(cls.tmpdir, "kadm5.acl"),
            )))

        cls.run_checked([
            cls.kdb5_util, "create", "-s", "-P", MASTER_PASSWORD,
        ])
        cls.run_checked([
            cls.kadmin_local, "-q",
            "addprinc -pw %s %s" % (CLIENT_PASSWORD, CLIENT_PRINC),
        ])
        cls.run_checked([
            cls.kadmin_local, "-q", "addprinc -randkey %s" % SERVER_PRINC,
        ])
        cls.run_checked([
            cls.kadmin_local, "-q",
            "ktadd -k %s -norandkey %s" % (cls.keytab, SERVER_PRINC),
        ])

        env = cls.krb5_env()
        cls.kdc = subprocess.Popen(
            [cls.krb5kdc, "-n"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.2)
        if cls.kdc.poll() is not None:
            stdout, stderr = cls.kdc.communicate()
            raise RuntimeError(
                "krb5kdc failed to start\nstdout:\n%s\nstderr:\n%s" %
                (output_text(stdout), output_text(stderr))
            )

        cls.run_checked(
            [cls.kinit, "-c", "FILE:%s" % cls.ccache, CLIENT_PRINC],
            input_text=CLIENT_PASSWORD + "\n",
        )

    @classmethod
    def tearDownClass(cls):
        kdc = getattr(cls, "kdc", None)
        if kdc is not None and kdc.poll() is None:
            kdc.terminate()
            try:
                kdc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                kdc.kill()
                kdc.wait()
        tmp = getattr(cls, "tmp", None)
        if tmp is not None:
            tmp.cleanup()

    @classmethod
    def krb5_env(cls):
        env = os.environ.copy()
        env["KRB5_CONFIG"] = cls.krb5_conf
        env["KRB5_KDC_PROFILE"] = cls.kdc_conf
        return env

    @classmethod
    def run_checked(cls, argv, input_text=None):
        env = cls.krb5_env()
        proc = subprocess.run(
            argv,
            env=env,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                "%s failed with %d\nstdout:\n%s\nstderr:\n%s" %
                (" ".join(argv), proc.returncode, proc.stdout, proc.stderr)
            )

    def side_path(self, name):
        return os.path.join(self.tmpdir, name)

    def read_json(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def read_bin(self, path):
        with open(path, "rb") as f:
            return f.read()

    def read_json_lines(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def read_unix_prelude(self, conn):
        buf = b""
        while b"END\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                raise EOFError("EOF before END")
            buf += chunk
        prelude, rest = buf.split(b"END\n", 1)
        return prelude.decode("utf-8").splitlines(), rest

    def server_env(self):
        env = os.environ.copy()
        env["KRB5_CONFIG"] = self.krb5_conf
        env["KRB5_KTNAME"] = "FILE:%s" % self.keytab
        return env

    def client_env(self):
        env = os.environ.copy()
        env["KRB5_CONFIG"] = self.krb5_conf
        env["KRB5CCNAME"] = "FILE:%s" % self.ccache
        return env

    def start_server(self, scenario, side, server_opts=(), max_connections=1,
                     no_fork=True):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()

        argv = [
            self.server_knc,
            "-l",
        ]
        if no_fork:
            argv.append("-f")
        argv += [
            "-M", str(max_connections),
            "-a", "127.0.0.1",
        ] + list(server_opts) + [
            str(port),
            sys.executable,
            self.helper,
            scenario,
            side,
        ]
        proc = subprocess.Popen(
            argv,
            env=self.server_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.1)
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            self.fail(
                "server failed to start\nstdout:\n%s\nstderr:\n%s" %
                (output_text(stdout), output_text(stderr))
            )
        return proc, port

    def start_unix_socket_server(self, unix_path, server_opts=()):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()

        argv = [
            self.server_knc,
            "-l",
            "-f",
            "-M", "1",
            "-a", "127.0.0.1",
            "-S", unix_path,
        ] + list(server_opts) + [
            str(port),
        ]
        proc = subprocess.Popen(
            argv,
            env=self.server_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.1)
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            self.fail(
                "server failed to start\nstdout:\n%s\nstderr:\n%s" %
                (output_text(stdout), output_text(stderr))
            )
        return proc, port

    def start_server_with_listener_fd_zero(self, scenario, side):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        port = listener.getsockname()[1]

        argv = [
            self.server_knc,
            "-l",
            "-f",
            "-M", "1",
            "-N", "0",
            sys.executable,
            self.helper,
            scenario,
            side,
        ]
        proc = subprocess.Popen(
            argv,
            env=self.server_env(),
            stdin=listener,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        listener.close()
        time.sleep(0.1)
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            self.fail(
                "server failed to start\nstdout:\n%s\nstderr:\n%s" %
                (output_text(stdout), output_text(stderr))
            )
        return proc, port

    def client_argv(self, port, client_opts=(), hostservice="host@127.0.0.1"):
        return [
            self.client_knc,
        ] + list(client_opts) + [
            hostservice,
            str(port),
        ]

    def client_argv_with_network_fd(self, fd, client_opts=(),
                                    hostservice="host@127.0.0.1"):
        return [
            self.client_knc,
        ] + list(client_opts) + [
            "-N", str(fd),
            hostservice,
        ]

    def finish_server(self, server):
        try:
            stdout, stderr = server.communicate(timeout=KNC_TIMEOUT)
        except subprocess.TimeoutExpired:
            server.kill()
            stdout, stderr = server.communicate()
            self.fail("server timed out\nstdout:\n%s\nstderr:\n%s" %
                      (output_text(stdout), output_text(stderr)))
        # The current listener path exits with 1 after a successful -M 1 run
        # because do_listener() returns 0 and main negates that value.
        self.assertIn(
            server.returncode, (0, 1),
            "server failed\nstdout:\n%s\nstderr:\n%s" %
            (output_text(stdout), output_text(stderr))
        )
        return stdout, stderr

    def run_client(self, port, input_data=b"", client_opts=(), env=None,
                   timeout=KNC_TIMEOUT, hostservice="host@127.0.0.1"):
        if env is None:
            env = self.client_env()
        client = subprocess.Popen(
            self.client_argv(port, client_opts, hostservice),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            cout, cerr = client.communicate(input_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            client.kill()
            cout, cerr = client.communicate()
            self.fail("client timed out\nstdout:\n%s\nstderr:\n%s" %
                      (output_text(cout), output_text(cerr)))
        return client.returncode, cout, cerr

    def run_client_with_wrapped_network_fd(self, port, input_data=b"",
                                           client_opts=(),
                                           timeout=KNC_TIMEOUT,
                                           hostservice="host@127.0.0.1"):
        net = socket.create_connection(("127.0.0.1", port))
        fd = net.fileno()
        client = subprocess.Popen(
            self.client_argv_with_network_fd(fd, client_opts, hostservice),
            env=self.client_env(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(fd,),
        )
        net.close()
        try:
            cout, cerr = client.communicate(input_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            client.kill()
            cout, cerr = client.communicate()
            self.fail("client timed out\nstdout:\n%s\nstderr:\n%s" %
                      (output_text(cout), output_text(cerr)))
        return client.returncode, cout, cerr

    def run_session(self, scenario, input_data=b"", server_opts=(),
                    client_opts=(), timeout=KNC_TIMEOUT):
        side = self.side_path("%s.json" % scenario)
        server, port = self.start_server(scenario, side, server_opts)
        try:
            returncode, cout, cerr = self.run_client(
                port, input_data, client_opts, timeout=timeout)
            self.assertEqual(
                returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(cout), output_text(cerr))
            )
            sout, serr = self.finish_server(server)
            return side, cout, cerr, sout, serr
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def read_exact_from(self, fd, length, timeout=KNC_TIMEOUT):
        chunks = []
        remaining = length
        deadline = time.time() + timeout
        while remaining:
            wait = deadline - time.time()
            self.assertGreater(wait, 0, "timed out reading client stdout")
            readable, _, _ = select.select([fd], [], [], wait)
            self.assertTrue(readable, "timed out reading client stdout")
            chunk = os.read(fd, remaining)
            self.assertNotEqual(chunk, b"", "unexpected EOF")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def run_interactive_request_response(self):
        side = self.side_path("request_response.json")
        server, port = self.start_server("request_response", side)
        try:
            client = subprocess.Popen(
                self.client_argv(port),
                env=self.client_env(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            client.stdin.write(b"alpha")
            client.stdin.flush()
            first = self.read_exact_from(client.stdout.fileno(), len(b"one:alpha"))
            client.stdin.write(b"beta")
            client.stdin.close()
            client.stdin = None
            rest, cerr = client.communicate(timeout=KNC_TIMEOUT)
            self.assertEqual(
                client.returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(first + rest), output_text(cerr))
            )
            self.finish_server(server)
            return side, first + rest
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def wait_for_json_event(self, path, event, timeout=KNC_TIMEOUT):
        deadline = time.time() + timeout
        seen = []
        while time.time() < deadline:
            if os.path.exists(path):
                seen = self.read_json_lines(path)
                if any(record.get("event") == event for record in seen):
                    return seen
            time.sleep(0.05)
        self.fail("timed out waiting for %s in %s; saw %r" %
                  (event, path, seen))

    def run_interactive_stdout_close_keeps_reading(self, data):
        side = self.side_path("stdout_close_keeps_reading.jsonl")
        server, port = self.start_server(
            "stdout_close_keeps_reading", side,
            server_opts=["-d", "-d"])
        client = None
        try:
            client = subprocess.Popen(
                self.client_argv(port, ["-d", "-d"]),
                env=self.client_env(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            events = self.wait_for_json_event(side, "stdout_closed")
            readable, _, _ = select.select(
                [client.stdout.fileno()], [], [], 2)
            self.assertTrue(
                readable,
                "client stdout did not see EOF after child closed stdout; "
                "events=%r" % events)
            eof = os.read(client.stdout.fileno(), 1)
            self.assertEqual(
                eof, b"",
                "client stdout produced data instead of EOF: %r" % eof)

            client.stdin.write(data)
            client.stdin.close()
            client.stdin = None
            rest, cerr = client.communicate(timeout=KNC_TIMEOUT)
            self.assertEqual(rest, b"")
            self.assertEqual(
                client.returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(rest), output_text(cerr))
            )
            self.finish_server(server)
            self.wait_for_json_event(side, "read_done")
            return side
        finally:
            if client is not None and client.poll() is None:
                if client.stdin is not None:
                    client.stdin.close()
                client.kill()
                client.wait()
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def test_exec_env_is_populated(self):
        side, out, _, _, _ = self.run_session("env")
        self.assertEqual(out, b"")
        env = self.read_json(side)
        self.assertEqual(env["KNC_MECH"], "krb5")
        self.assertTrue(env["KNC_CREDS"])
        self.assertTrue(env["KNC_EXPORT_NAME"])
        self.assertEqual(env["KNC_REMOTE_ADDR"], "127.0.0.1")
        self.assertEqual(env["KNC_REMOTE_IP"], "127.0.0.1")
        self.assertIsNone(env["KNC_REMOTE_IP6"])
        self.assertTrue(env["KNC_REMOTE_PORT"])
        self.assertTrue(env["KNC_VERSION"])

    def test_exec_stdin_binary(self):
        data = b"\x00knc stdin\x00" + deterministic_payload(100000)
        side, out, _, _, _ = self.run_session("stdin_binary", data)
        self.assertEqual(out, b"")
        self.assertEqual(self.read_bin(side), data)

    def test_exec_stdout_binary(self):
        expected = deterministic_payload(65537)
        side, out, _, _, _ = self.run_session("stdout_binary")
        self.assertEqual(out, expected)
        result = self.read_json(side)
        self.assertEqual(result["len"], len(expected))
        self.assertEqual(result["sha256"], sha256(expected))

    def test_exec_request_response_before_close(self):
        side, out = self.run_interactive_request_response()
        self.assertEqual(out, b"one:alphatwo:beta")
        self.assertEqual(self.read_json(side), {"rest": ""})

    def test_exec_large_request_response_does_not_deadlock(self):
        data = deterministic_payload(1024 * 1024 + 8193)
        expected = deterministic_payload(512 * 1024 + 29)
        side, out, _, _, _ = self.run_session("large_request_response", data)
        self.assertEqual(out, expected)
        result = self.read_json(side)
        self.assertEqual(result["input"]["len"], len(data))
        self.assertEqual(result["input"]["sha256"], sha256(data))
        self.assertEqual(result["response"]["len"], len(expected))
        self.assertEqual(result["response"]["sha256"], sha256(expected))

    def test_client_wraps_existing_network_fd_with_N(self):
        side = self.side_path("wrapped_network_fd.jsonl")
        server, port = self.start_server("connection_marker", side)
        try:
            payload = b"wrapped network fd"
            returncode, out, err = self.run_client_with_wrapped_network_fd(
                port, payload)
            self.assertEqual(
                returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out), output_text(err))
            )
            self.assertEqual(out, b"conn:" + payload)
            self.finish_server(server)
            records = self.read_json_lines(side)
            self.assertEqual(len(records), 1)
            self.assertEqual(
                base64.b64decode(records[0]["data"].encode("ascii")),
                payload,
            )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def test_listener_wraps_listener_fd_zero_with_N(self):
        side = self.side_path("listener_fd_zero.jsonl")
        server, port = self.start_server_with_listener_fd_zero(
            "connection_marker", side)
        try:
            payload = b"listener fd zero"
            returncode, out, err = self.run_client(port, payload)
            self.assertEqual(
                returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out), output_text(err))
            )
            self.assertEqual(out, b"conn:" + payload)
            self.finish_server(server)
            records = self.read_json_lines(side)
            self.assertEqual(len(records), 1)
            self.assertEqual(
                base64.b64decode(records[0]["data"].encode("ascii")),
                payload,
            )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def test_client_explicit_principal_with_P(self):
        side = self.side_path("explicit_principal.jsonl")
        server, port = self.start_server("connection_marker", side)
        try:
            payload = b"explicit principal"
            returncode, out, err = self.run_client(
                port, payload,
                client_opts=["-P", SERVER_PRINC],
                hostservice="notservice@127.0.0.1")
            self.assertEqual(
                returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out), output_text(err))
            )
            self.assertEqual(out, b"conn:" + payload)
            self.finish_server(server)
            records = self.read_json_lines(side)
            self.assertEqual(len(records), 1)
            self.assertEqual(
                base64.b64decode(records[0]["data"].encode("ascii")),
                payload,
            )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def test_client_empty_stdin_relays_eof(self):
        side = self.side_path("empty_stdin.jsonl")
        server, port = self.start_server("connection_marker", side)
        try:
            returncode, out, err = self.run_client(port, b"")
            self.assertEqual(
                returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out), output_text(err))
            )
            self.assertEqual(out, b"conn:")
            self.finish_server(server)
            records = self.read_json_lines(side)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["len"], 0)
            self.assertEqual(records[0]["sha256"], sha256(b""))
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def test_client_and_server_request_krb5_mechanism_with_m(self):
        side = self.side_path("requested_krb5_mech.jsonl")
        opts = ["-m", "krb5"]
        server, port = self.start_server(
            "connection_marker", side, server_opts=opts)
        try:
            payload = b"requested krb5 mechanism"
            returncode, out, err = self.run_client(
                port, payload, client_opts=opts)
            self.assertEqual(
                returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out), output_text(err))
            )
            self.assertEqual(out, b"conn:" + payload)
            self.finish_server(server)
            records = self.read_json_lines(side)
            self.assertEqual(len(records), 1)
            self.assertEqual(
                base64.b64decode(records[0]["data"].encode("ascii")),
                payload,
            )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def test_client_stdio_mode_relays_without_local_program(self):
        side = self.side_path("client_stdio.jsonl")
        server, port = self.start_server("connection_marker", side)
        try:
            payload = b"client stdio relay"
            returncode, out, err = self.run_client(port, payload)
            self.assertEqual(
                returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out), output_text(err))
            )
            self.assertEqual(out, b"conn:" + payload)
            self.finish_server(server)
            records = self.read_json_lines(side)
            self.assertEqual(len(records), 1)
            self.assertEqual(
                base64.b64decode(records[0]["data"].encode("ascii")),
                payload,
            )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def test_exec_client_half_close_still_permits_child_response(self):
        data = b"half-close request"
        side, out, _, _, _ = self.run_session("client_half_close", data)
        self.assertEqual(out, b"after-eof:" + data)
        self.assertEqual(self.read_json(side)["write_status"], "written")

    def test_exec_drains_network_input_before_child_eof(self):
        data = deterministic_payload(1024 * 1024 + 17)
        side, out, _, _, _ = self.run_session("drain_before_eof", data)
        self.assertEqual(out, b"")
        result = self.read_json(side)
        self.assertEqual(result["len"], len(data))
        self.assertEqual(result["sha256"], sha256(data))

    def test_exec_child_output_then_exit_is_not_truncated(self):
        expected = deterministic_payload(1024 * 1024 + 333)
        _, out, _, _, _ = self.run_session("child_output_then_exit")
        self.assertEqual(out, expected)

    def test_exec_child_stdout_close_still_allows_child_stdin(self):
        data = deterministic_payload(196613)
        side = self.run_interactive_stdout_close_keeps_reading(data)
        events = self.read_json_lines(side)
        self.assertIn({"event": "stdout_closed"}, events)
        done = [event for event in events if event.get("event") == "read_done"]
        self.assertEqual(len(done), 1, events)
        self.assertEqual(done[0]["len"], len(data))
        self.assertEqual(done[0]["sha256"], sha256(data))

    def test_exec_stderr_is_not_tunneled(self):
        side, out, _, _, _ = self.run_session("stderr_not_tunneled")
        self.assertEqual(out, b"stdout-marker\n")
        self.assertEqual(self.read_json(side)["stderr"], "stderr-marker\n")

    def test_no_half_close_drops_response_after_client_eof(self):
        data = b"no-half-close request"
        opts = ["-o", "no-half-close"]
        side, out, _, _, _ = self.run_session(
            "client_half_close", data, server_opts=opts, client_opts=opts)
        self.assertEqual(out, b"")
        self.assertIn(
            self.read_json(side)["write_status"],
            ["written", "broken-pipe"],
        )

    def test_auth_failure_does_not_exec_helper(self):
        side = self.side_path("auth_failure.json")
        server, port = self.start_server("env", side)
        try:
            env = self.client_env()
            env["KRB5CCNAME"] = "FILE:%s" % self.side_path("missing.ccache")
            returncode, out, err = self.run_client(port, env=env)
            self.assertNotEqual(
                returncode, 0,
                "client unexpectedly succeeded\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out), output_text(err))
            )
            self.finish_server(server)
            self.assertFalse(os.path.exists(side))
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def test_unix_socket_mode_sends_credential_prelude_then_data(self):
        unix_path = self.side_path("knc.sock")
        side = self.side_path("unix_socket.json")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(unix_path)
        listener.listen(1)
        result = {}

        def unix_worker():
            try:
                conn, _ = listener.accept()
                with conn:
                    prelude, rest = self.read_unix_prelude(conn)
                    data = [rest]
                    while True:
                        chunk = conn.recv(8192)
                        if not chunk:
                            break
                        data.append(chunk)
                    payload = b"".join(data)
                    conn.sendall(b"unix-response:" + payload)
                    result["prelude"] = prelude
                    result["payload"] = base64.b64encode(payload).decode("ascii")
            except BaseException as e:
                result["error"] = repr(e)
            finally:
                listener.close()

        thread = threading.Thread(target=unix_worker)
        thread.start()
        server, port = self.start_unix_socket_server(unix_path)
        try:
            payload = b"unix-socket request"
            returncode, out, err = self.run_client(port, payload)
            self.assertEqual(
                returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out), output_text(err))
            )
            self.finish_server(server)
            thread.join(KNC_TIMEOUT)
            self.assertFalse(thread.is_alive())
            self.assertNotIn("error", result)
            self.assertEqual(out, b"unix-response:" + payload)
            prelude = {}
            for line in result["prelude"]:
                key, value = line.split(":", 1)
                prelude[key] = value
            self.assertEqual(prelude["MECH"], "krb5")
            self.assertTrue(prelude["CREDS"])
            self.assertTrue(prelude["EXPORT_NAME"])
            self.assertEqual(prelude["REMOTE_ADDR"], "127.0.0.1")
            self.assertEqual(prelude["REMOTE_IP"], "127.0.0.1")
            self.assertTrue(prelude["REMOTE_PORT"])
            self.assertTrue(prelude["VERSION"])
            self.assertEqual(
                base64.b64decode(result["payload"].encode("ascii")),
                payload,
            )
            with open(side, "w", encoding="utf-8") as f:
                json.dump(result, f, sort_keys=True)
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
            thread.join(2)
            listener.close()

    def test_unix_socket_daemon_eof_still_allows_client_input(self):
        unix_path = self.side_path("knc-eof-first.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(unix_path)
        listener.listen(1)
        result = {}

        def unix_worker():
            try:
                conn, _ = listener.accept()
                with conn:
                    prelude, rest = self.read_unix_prelude(conn)
                    conn.sendall(b"daemon-eof")
                    conn.shutdown(socket.SHUT_WR)
                    data = [rest]
                    while True:
                        chunk = conn.recv(8192)
                        if not chunk:
                            break
                        data.append(chunk)
                    payload = b"".join(data)
                    result["prelude"] = prelude
                    result["payload"] = base64.b64encode(payload).decode("ascii")
            except BaseException as e:
                result["error"] = repr(e)
            finally:
                listener.close()

        thread = threading.Thread(target=unix_worker)
        thread.start()
        server, port = self.start_unix_socket_server(unix_path)
        client = None
        try:
            payload = b"client data after daemon eof"
            client = subprocess.Popen(
                self.client_argv(port),
                env=self.client_env(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            out = self.read_exact_from(client.stdout.fileno(), len(b"daemon-eof"))
            self.assertEqual(out, b"daemon-eof")
            readable, _, _ = select.select([client.stdout.fileno()], [], [], 2)
            self.assertTrue(readable, "client stdout did not receive daemon EOF")
            self.assertEqual(os.read(client.stdout.fileno(), 1), b"")

            client.stdin.write(payload)
            client.stdin.close()
            client.stdin = None
            rest, err = client.communicate(timeout=KNC_TIMEOUT)
            self.assertEqual(rest, b"")
            self.assertEqual(
                client.returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(rest), output_text(err))
            )
            self.finish_server(server)
            thread.join(KNC_TIMEOUT)
            self.assertFalse(thread.is_alive())
            self.assertNotIn("error", result)
            self.assertEqual(
                base64.b64decode(result["payload"].encode("ascii")),
                payload,
            )
        finally:
            if client is not None and client.poll() is None:
                if client.stdin is not None:
                    client.stdin.close()
                client.kill()
                client.wait()
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
            thread.join(2)
            listener.close()

    def test_unix_socket_no_half_close_drops_daemon_response_after_client_eof(self):
        unix_path = self.side_path("knc-no-half-close.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(unix_path)
        listener.listen(1)
        result = {}

        def unix_worker():
            try:
                conn, _ = listener.accept()
                with conn:
                    _, rest = self.read_unix_prelude(conn)
                    data = [rest]
                    while True:
                        chunk = conn.recv(8192)
                        if not chunk:
                            break
                        data.append(chunk)
                    payload = b"".join(data)
                    status = "not-written"
                    try:
                        conn.sendall(b"late-unix-response:" + payload)
                        status = "written"
                    except BrokenPipeError:
                        status = "broken-pipe"
                    result["payload"] = base64.b64encode(payload).decode("ascii")
                    result["write_status"] = status
            except BaseException as e:
                result["error"] = repr(e)
            finally:
                listener.close()

        thread = threading.Thread(target=unix_worker)
        thread.start()
        opts = ["-o", "no-half-close"]
        server, port = self.start_unix_socket_server(unix_path, server_opts=opts)
        try:
            payload = b"unix no half close"
            returncode, out, err = self.run_client(port, payload, client_opts=opts)
            self.assertEqual(
                returncode, 0,
                "client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out), output_text(err))
            )
            self.assertEqual(out, b"")
            self.finish_server(server)
            thread.join(KNC_TIMEOUT)
            self.assertFalse(thread.is_alive())
            self.assertNotIn("error", result)
            self.assertEqual(
                base64.b64decode(result["payload"].encode("ascii")),
                payload,
            )
            self.assertIn(result["write_status"], ["written", "broken-pipe"])
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
            thread.join(2)
            listener.close()

    def test_listener_processes_two_forked_exec_connections(self):
        side = self.side_path("connection_markers.jsonl")
        server, port = self.start_server(
            "connection_marker", side, max_connections=2, no_fork=False)
        try:
            rc1, out1, err1 = self.run_client(port, b"first")
            rc2, out2, err2 = self.run_client(port, b"second")
            self.assertEqual(
                rc1, 0,
                "first client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out1), output_text(err1))
            )
            self.assertEqual(
                rc2, 0,
                "second client failed\nstdout:\n%s\nstderr:\n%s" %
                (output_text(out2), output_text(err2))
            )
            self.assertEqual(out1, b"conn:first")
            self.assertEqual(out2, b"conn:second")
            self.finish_server(server)
            seen = sorted(
                base64.b64decode(record["data"].encode("ascii"))
                for record in self.read_json_lines(side)
            )
            self.assertEqual(seen, [b"first", b"second"])
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--knc", default=os.path.join("bin", "knc"),
                        help="path to use for both knc client and server")
    parser.add_argument("--client-knc",
                        help="path to the knc executable to run as client")
    parser.add_argument("--server-knc",
                        help="path to the knc executable to run as server")
    args, unittest_args = parser.parse_known_args()

    KNCExecTests.knc_path = args.knc
    KNCExecTests.client_knc_path = args.client_knc
    KNCExecTests.server_knc_path = args.server_knc
    have_kimpersonate = all(
        shutil.which(tool) is not None for tool in ("ktutil", "kimpersonate")
    )
    local_kdc_tools = ("kdb5_util", "kadmin.local", "krb5kdc", "kinit")
    missing_kdc_tools = [
        tool for tool in local_kdc_tools if shutil.which(tool) is None
    ]
    if not have_kimpersonate and missing_kdc_tools:
        print(
            "missing optional test dependencies: kimpersonate or %s" %
            ", ".join(missing_kdc_tools),
            file=sys.stderr,
        )
        return 77

    if unittest_args:
        suite = unittest.defaultTestLoader.loadTestsFromNames(
            unittest_args, module=sys.modules[__name__])
    else:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(KNCExecTests)
    runner = unittest.TextTestRunner(verbosity=2)
    try:
        result = runner.run(suite)
    except MissingTool as e:
        print("missing optional test dependency: %s" % e, file=sys.stderr)
        return 77
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
