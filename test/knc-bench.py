#!/usr/bin/env python3
#
# Optional black-box benchmark for the knc executable.  This deliberately uses
# kimpersonate and a local keytab/ccache so it does not need a KDC.

import argparse
import hashlib
import json
import os
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import textwrap
import time


REALM = "KNC.TEST"
CLIENT_PRINC = "client@%s" % REALM
SERVER_PRINC = "host/127.0.0.1@%s" % REALM
ENCTYPE = "aes256-cts-hmac-sha1-96"
TIMEOUT = 60
MIB = 1024 * 1024


HELPER = r'''
#!/usr/bin/env python3
import hashlib
import json
import os
import sys


def payload(size):
    return bytes(((i * 31 + 7) & 0xff) for i in range(size))


def write_all(data):
    view = memoryview(data)
    while view:
        written = os.write(1, view)
        view = view[written:]


def digest_parts(parts):
    h = hashlib.sha256()
    total = 0
    for part in parts:
        total += len(part)
        h.update(part)
    return {"len": total, "sha256": h.hexdigest()}


def read_all_parts():
    parts = []
    while True:
        data = os.read(0, 65536)
        if not data:
            break
        parts.append(data)
    return parts


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True)
    os.rename(tmp, path)


scenario = sys.argv[1]
side = sys.argv[2]

if scenario == "sink":
    write_json(side, digest_parts(read_all_parts()))

elif scenario == "source":
    size = int(sys.argv[3])
    data = payload(size)
    write_all(data)
    write_json(side, digest_parts([data]))

elif scenario == "echo":
    parts = read_all_parts()
    for part in parts:
        write_all(part)
    write_json(side, digest_parts(parts))

elif scenario == "duplex":
    size = int(sys.argv[3])
    parts = []
    first = os.read(0, 8192)
    if first:
        parts.append(first)
    data = payload(size)
    write_all(data)
    parts.extend(read_all_parts())
    write_json(side, {
        "input": digest_parts(parts),
        "output": digest_parts([data]),
    })

else:
    raise SystemExit("unknown scenario: %s" % scenario)
'''


def deterministic_payload(size):
    return bytes(((i * 31 + 7) & 0xff) for i in range(size))


def digest(data):
    return {"len": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def median(values):
    return statistics.median(values)


class BenchError(RuntimeError):
    pass


class Case:
    def __init__(self, name, scenario, input_size, output_size,
                 helper_args=()):
        self.name = name
        self.scenario = scenario
        self.input_size = input_size
        self.output_size = output_size
        self.helper_args = tuple(helper_args)
        self.input_data = deterministic_payload(input_size)
        self.expected_input = digest(self.input_data)
        self.expected_output = (
            digest(deterministic_payload(output_size))
            if output_size
            else digest(b"")
        )

    @property
    def total_bytes(self):
        return self.input_size + self.output_size


class Binary:
    def __init__(self, label, path):
        self.label = label
        self.path = os.path.abspath(path)


class Bench:
    def __init__(self, old_knc, new_knc):
        self.binaries = [
            Binary("old", old_knc),
            Binary("new", new_knc),
        ]
        self.tmp = tempfile.TemporaryDirectory(prefix="knc-bench.")
        self.tmpdir = self.tmp.name
        self.helper = os.path.join(self.tmpdir, "knc_bench_helper.py")
        self.keytab = os.path.join(self.tmpdir, "server.keytab")
        self.ccache = os.path.join(self.tmpdir, "client.ccache")
        self.krb5_conf = os.path.join(self.tmpdir, "krb5.conf")

    def close(self):
        self.tmp.cleanup()

    def setup(self):
        for binary in self.binaries:
            if not os.path.exists(binary.path):
                raise BenchError(
                    "%s knc executable not found: %s" %
                    (binary.label, binary.path)
                )
            if not os.access(binary.path, os.X_OK):
                raise BenchError(
                    "%s knc executable is not executable: %s" %
                    (binary.label, binary.path)
                )

        ktutil = shutil.which("ktutil")
        kimpersonate = shutil.which("kimpersonate")
        if ktutil is None:
            raise BenchError("ktutil not found")
        if kimpersonate is None:
            raise BenchError("kimpersonate not found")

        with open(self.helper, "w", encoding="utf-8") as f:
            f.write(textwrap.dedent(HELPER))
        os.chmod(self.helper, 0o755)

        with open(self.krb5_conf, "w", encoding="utf-8") as f:
            f.write(textwrap.dedent("""\
                [libdefaults]
                    default_realm = {realm}
                    dns_lookup_kdc = false
                    dns_lookup_realm = false
                    rdns = false
                    dns_canonicalize_hostname = false
                    ticket_lifetime = 1h
            """.format(realm=REALM)))

        self.run_checked([
            ktutil, "-k", self.keytab, "add",
            "--principal=%s" % SERVER_PRINC,
            "--kvno=1",
            "--enctype=%s" % ENCTYPE,
            "--password=knc-bench-password",
        ])
        self.run_checked([
            kimpersonate,
            "--krb5",
            "--client=%s" % CLIENT_PRINC,
            "--server=%s" % SERVER_PRINC,
            "--keytab=%s" % self.keytab,
            "--ccache=FILE:%s" % self.ccache,
            "--enc-type=%s" % ENCTYPE,
            "--session-enc-type=%s" % ENCTYPE,
        ])

    def env(self, mode):
        env = os.environ.copy()
        env["KRB5_CONFIG"] = self.krb5_conf
        if mode == "server":
            env["KRB5_KTNAME"] = "FILE:%s" % self.keytab
        else:
            env["KRB5CCNAME"] = "FILE:%s" % self.ccache
        return env

    def run_checked(self, argv):
        proc = subprocess.run(
            argv,
            env=self.env("client"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            raise BenchError(
                "%s failed with %d\nstdout:\n%s\nstderr:\n%s" %
                (" ".join(argv), proc.returncode, proc.stdout, proc.stderr)
            )

    def start_server(self, binary, case, side):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()

        argv = [
            binary.path,
            "-l",
            "-f",
            "-M", "1",
            "-a", "127.0.0.1",
            str(port),
            sys.executable,
            self.helper,
            case.scenario,
            side,
        ] + list(case.helper_args)
        proc = subprocess.Popen(
            argv,
            env=self.env("server"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.1)
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            raise BenchError(
                "%s server failed to start for %s\nstdout:\n%s\nstderr:\n%s" %
                (binary.label, case.name, show(stdout), show(stderr))
            )
        return proc, port

    def run_client(self, binary, port, input_data):
        argv = [binary.path, "host@127.0.0.1", str(port)]
        client = subprocess.Popen(
            argv,
            env=self.env("client"),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = client.communicate(input_data, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            client.kill()
            stdout, stderr = client.communicate()
            raise BenchError(
                "%s client timed out\nstdout:\n%s\nstderr:\n%s" %
                (binary.label, show(stdout), show(stderr))
            )
        if client.returncode != 0:
            raise BenchError(
                "%s client failed with %d\nstdout:\n%s\nstderr:\n%s" %
                (binary.label, client.returncode, show(stdout), show(stderr))
            )
        return stdout

    def finish_server(self, binary, case, server):
        try:
            stdout, stderr = server.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            server.kill()
            stdout, stderr = server.communicate()
            raise BenchError(
                "%s server timed out for %s\nstdout:\n%s\nstderr:\n%s" %
                (binary.label, case.name, show(stdout), show(stderr))
            )
        if server.returncode not in (0, 1):
            raise BenchError(
                "%s server failed with %d for %s\nstdout:\n%s\nstderr:\n%s" %
                (binary.label, server.returncode, case.name,
                 show(stdout), show(stderr))
            )

    def run_once(self, binary, case, number):
        side = os.path.join(
            self.tmpdir,
            "%s.%s.%d.json" % (binary.label, case.name, number),
        )
        server, port = self.start_server(binary, case, side)
        try:
            start = time.perf_counter()
            stdout = self.run_client(binary, port, case.input_data)
            self.finish_server(binary, case, server)
            elapsed = time.perf_counter() - start
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

        self.validate(case, side, stdout)
        return elapsed

    def validate(self, case, side, stdout):
        with open(side, "r", encoding="utf-8") as f:
            result = json.load(f)

        if case.scenario == "duplex":
            got_input = result["input"]
            got_output = result["output"]
        elif case.scenario == "source":
            got_input = case.expected_input
            got_output = digest(stdout)
            if result != case.expected_output:
                raise BenchError(
                    "%s side digest mismatch: got %r expected %r" %
                    (case.name, result, case.expected_output)
                )
        else:
            got_input = result
            got_output = digest(stdout)

        if got_input != case.expected_input:
            raise BenchError(
                "%s input digest mismatch: got %r expected %r" %
                (case.name, got_input, case.expected_input)
            )
        if got_output != case.expected_output:
            raise BenchError(
                "%s output digest mismatch: got %r expected %r" %
                (case.name, got_output, case.expected_output)
            )


def show(data):
    limit = 4096
    text = data[:limit].decode("utf-8", "replace")
    if len(data) > limit:
        text += "\n[truncated to %d of %d bytes]" % (limit, len(data))
    return text


def throughput(total_bytes, elapsed):
    if elapsed <= 0:
        return 0
    return total_bytes / elapsed / MIB


def default_cases(args):
    return [
        Case("tiny-echo", "echo", 1, 1),
        Case("upload-%dm" % (args.bulk_size // MIB), "sink",
             args.bulk_size, 0),
        Case("download-%dm" % (args.bulk_size // MIB), "source",
             0, args.bulk_size, [str(args.bulk_size)]),
        Case("duplex-%dm" % (args.duplex_size // MIB), "duplex",
             args.duplex_size, args.duplex_size, [str(args.duplex_size)]),
    ]


def print_results(results, cases, binaries):
    print("")
    print("%-14s %-8s %10s %10s %10s" %
          ("case", "binary", "median-s", "min-s", "MiB/s"))
    print("%-14s %-8s %10s %10s %10s" %
          ("-" * 14, "-" * 8, "-" * 10, "-" * 10, "-" * 10))
    for case in cases:
        for binary in binaries:
            values = results[(case.name, binary.label)]
            med = median(values)
            print("%-14s %-8s %10.4f %10.4f %10.2f" %
                  (case.name, binary.label, med, min(values),
                   throughput(case.total_bytes, med)))

    print("")
    print("%-14s %10s %12s %12s" %
          ("case", "new/old-s", "old-MiB/s", "new-MiB/s"))
    print("%-14s %10s %12s %12s" %
          ("-" * 14, "-" * 10, "-" * 12, "-" * 12))
    for case in cases:
        old_med = median(results[(case.name, "old")])
        new_med = median(results[(case.name, "new")])
        old_tput = throughput(case.total_bytes, old_med)
        new_tput = throughput(case.total_bytes, new_med)
        print("%-14s %10.3f %12.2f %12.2f" %
              (case.name, new_med / old_med, old_tput, new_tput))


def parse_args():
    top = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(
        description="Compare old and new knc executable throughput."
    )
    parser.add_argument(
        "--old-knc", default="/usr/local/bin/knc",
        help="old knc executable, default: /usr/local/bin/knc",
    )
    parser.add_argument(
        "--new-knc", default=os.path.join(top, "bin", "knc"),
        help="new knc executable, default: ../bin/knc",
    )
    parser.add_argument(
        "--iterations", type=int, default=5,
        help="measured iterations per case and binary",
    )
    parser.add_argument(
        "--warmups", type=int, default=1,
        help="unmeasured warmup iterations per case and binary",
    )
    parser.add_argument(
        "--bulk-size", type=int, default=8 * MIB,
        help="bytes for upload/download cases",
    )
    parser.add_argument(
        "--duplex-size", type=int, default=4 * MIB,
        help="bytes in each direction for duplex case",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.iterations < 1:
        raise SystemExit("--iterations must be at least 1")
    if args.warmups < 0:
        raise SystemExit("--warmups must be non-negative")

    bench = Bench(args.old_knc, args.new_knc)
    try:
        bench.setup()
        cases = default_cases(args)
        results = {}

        print("old: %s" % os.path.abspath(args.old_knc))
        print("new: %s" % os.path.abspath(args.new_knc))
        print("iterations: %d, warmups: %d" %
              (args.iterations, args.warmups))

        for case in cases:
            print("case: %s" % case.name)
            for _ in range(args.warmups):
                for binary in bench.binaries:
                    bench.run_once(binary, case, -1)

            for i in range(args.iterations):
                for binary in bench.binaries:
                    elapsed = bench.run_once(binary, case, i)
                    results.setdefault(
                        (case.name, binary.label), []
                    ).append(elapsed)
                    print("  %-3s iter %d: %.4fs" %
                          (binary.label, i + 1, elapsed))

        print_results(results, cases, bench.binaries)
    finally:
        bench.close()


if __name__ == "__main__":
    try:
        main()
    except BenchError as e:
        raise SystemExit(str(e))
