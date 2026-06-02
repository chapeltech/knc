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
TIMEOUT = 180
MIB = 1024 * 1024
_DIGEST_CACHE = {}


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


def deterministic_chunks(size, chunk_size=MIB):
    offset = 0
    while offset < size:
        length = min(chunk_size, size - offset)
        yield bytes(
            (((i + offset) * 31 + 7) & 0xff) for i in range(length)
        )
        offset += length


def deterministic_payload(size):
    return b"".join(deterministic_chunks(size))


def digest(data):
    return {"len": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def deterministic_digest(size):
    if size in _DIGEST_CACHE:
        return dict(_DIGEST_CACHE[size])

    h = hashlib.sha256()
    for chunk in deterministic_chunks(size):
        h.update(chunk)
    ret = {"len": size, "sha256": h.hexdigest()}
    _DIGEST_CACHE[size] = ret
    return dict(ret)


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
        self._expected_input = None
        self._expected_output = None

    @property
    def total_bytes(self):
        return self.input_size + self.output_size

    @property
    def expected_input(self):
        if self._expected_input is None:
            self._expected_input = deterministic_digest(self.input_size)
        return self._expected_input

    @property
    def expected_output(self):
        if self._expected_output is None:
            self._expected_output = deterministic_digest(self.output_size)
        return self._expected_output

    def input_data(self):
        return deterministic_payload(self.input_size)


class Binary:
    def __init__(self, label, path):
        self.label = label
        self.path = os.path.abspath(path)


class Pair:
    def __init__(self, client, server):
        self.client = client
        self.server = server
        self.label = "%s-%s" % (client.label, server.label)


class Bench:
    def __init__(self, old_knc, new_knc):
        self.old = Binary("old", old_knc)
        self.new = Binary("new", new_knc)
        self.binaries = [self.old, self.new]
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

    def pairs(self, mode):
        if mode == "same":
            return [
                Pair(self.old, self.old),
                Pair(self.new, self.new),
            ]

        return [
            Pair(self.old, self.old),
            Pair(self.new, self.old),
            Pair(self.old, self.new),
            Pair(self.new, self.new),
        ]

    def start_server(self, pair, case, side):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()

        argv = [
            pair.server.path,
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
                (pair.label, case.name, show(stdout), show(stderr))
            )
        return proc, port

    def run_client(self, pair, port, input_data):
        argv = [pair.client.path, "host@127.0.0.1", str(port)]
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
                (pair.label, show(stdout), show(stderr))
            )
        if client.returncode != 0:
            raise BenchError(
                "%s client failed with %d\nstdout:\n%s\nstderr:\n%s" %
                (pair.label, client.returncode, show(stdout), show(stderr))
            )
        return stdout

    def finish_server(self, pair, case, server):
        try:
            stdout, stderr = server.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            server.kill()
            stdout, stderr = server.communicate()
            raise BenchError(
                "%s server timed out for %s\nstdout:\n%s\nstderr:\n%s" %
                (pair.label, case.name, show(stdout), show(stderr))
            )
        if server.returncode not in (0, 1):
            raise BenchError(
                "%s server failed with %d for %s\nstdout:\n%s\nstderr:\n%s" %
                (pair.label, server.returncode, case.name,
                 show(stdout), show(stderr))
            )

    def run_once(self, pair, case, number, input_data):
        side = os.path.join(
            self.tmpdir,
            "%s.%s.%d.json" % (pair.label, case.name, number),
        )
        server, port = self.start_server(pair, case, side)
        try:
            start = time.perf_counter()
            stdout = self.run_client(pair, port, input_data)
            self.finish_server(pair, case, server)
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


def parse_sizes_mib(value):
    sizes = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        size = int(part)
        if size <= 0:
            raise argparse.ArgumentTypeError(
                "sizes must be positive MiB values"
            )
        sizes.append(size * MIB)
    if not sizes:
        raise argparse.ArgumentTypeError("empty size list")
    return sizes


def parse_cases(value):
    valid = {"tiny", "upload", "download", "duplex"}
    cases = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if part not in valid:
            raise argparse.ArgumentTypeError(
                "unknown case %s, expected one of %s" %
                (part, ",".join(sorted(valid)))
            )
        cases.append(part)
    if not cases:
        raise argparse.ArgumentTypeError("empty case list")
    return cases


def default_cases(args):
    cases = []

    if "tiny" in args.cases:
        cases.append(Case("tiny-echo", "echo", 1, 1))

    if args.sizes_mib is None:
        bulk_sizes = [args.bulk_size]
        duplex_sizes = [args.duplex_size]
    else:
        bulk_sizes = args.sizes_mib
        duplex_sizes = args.sizes_mib

    for size in bulk_sizes:
        mib = size // MIB
        if "upload" in args.cases:
            cases.append(Case("upload-%dm" % mib, "sink", size, 0))
        if "download" in args.cases:
            cases.append(Case("download-%dm" % mib, "source",
                              0, size, [str(size)]))

    for size in duplex_sizes:
        mib = size // MIB
        if "duplex" in args.cases:
            cases.append(Case("duplex-%dm" % mib, "duplex",
                              size, size, [str(size)]))

    return cases


def print_results(results, cases, pairs):
    print("")
    print("%-14s %-8s %10s %10s %10s" %
          ("case", "pair", "median-s", "min-s", "MiB/s"))
    print("%-14s %-8s %10s %10s %10s" %
          ("-" * 14, "-" * 8, "-" * 10, "-" * 10, "-" * 10))
    for case in cases:
        for pair in pairs:
            values = results[(case.name, pair.label)]
            med = median(values)
            print("%-14s %-8s %10.4f %10.4f %10.2f" %
                  (case.name, pair.label, med, min(values),
                   throughput(case.total_bytes, med)))

    print("")
    print("%-14s %-8s %12s %12s" %
          ("case", "pair", "vs-oldold", "MiB/s"))
    print("%-14s %-8s %12s %12s" %
          ("-" * 14, "-" * 8, "-" * 12, "-" * 12))
    for case in cases:
        base = median(results[(case.name, "old-old")])
        for pair in pairs:
            med = median(results[(case.name, pair.label)])
            print("%-14s %-8s %12.3f %12.2f" %
                  (case.name, pair.label, med / base,
                   throughput(case.total_bytes, med)))


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
    parser.add_argument(
        "--sizes-mib", type=parse_sizes_mib,
        help="comma-separated MiB sizes for upload/download/duplex cases",
    )
    parser.add_argument(
        "--cases", type=parse_cases,
        default=parse_cases("tiny,upload,download,duplex"),
        help="comma-separated cases: tiny,upload,download,duplex",
    )
    parser.add_argument(
        "--pairs", choices=["same", "mixed"], default="same",
        help="same runs old-old and new-new; mixed runs all client/server pairs",
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
        pairs = bench.pairs(args.pairs)
        results = {}

        print("old: %s" % os.path.abspath(args.old_knc))
        print("new: %s" % os.path.abspath(args.new_knc))
        print("iterations: %d, warmups: %d" %
              (args.iterations, args.warmups))
        print("pairs: %s" % ", ".join(pair.label for pair in pairs))

        for case in cases:
            print("case: %s" % case.name)
            input_data = case.input_data()
            for _ in range(args.warmups):
                for pair in pairs:
                    bench.run_once(pair, case, -1, input_data)

            for i in range(args.iterations):
                for pair in pairs:
                    elapsed = bench.run_once(pair, case, i, input_data)
                    results.setdefault(
                        (case.name, pair.label), []
                    ).append(elapsed)
                    print("  %-8s iter %d: %.4fs" %
                          (pair.label, i + 1, elapsed))

        print_results(results, cases, pairs)
    finally:
        bench.close()


if __name__ == "__main__":
    try:
        main()
    except BenchError as e:
        raise SystemExit(str(e))
