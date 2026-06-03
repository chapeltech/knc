#!/usr/bin/env python3
#
# Optional throughput benchmark for knc.  This uses system producers and
# consumers for the data path so Python only orchestrates the runs.

import argparse
import os
import shutil
import signal
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


def median(values):
    return statistics.median(values)


def throughput(mib, elapsed):
    if elapsed <= 0:
        return 0
    return mib / elapsed


def parse_csv(value):
    ret = []
    for part in value.split(","):
        part = part.strip()
        if part:
            ret.append(part)
    if not ret:
        raise argparse.ArgumentTypeError("empty list")
    return ret


def parse_sizes_mib(value):
    sizes = []
    for part in parse_csv(value):
        size = int(part)
        if size <= 0:
            raise argparse.ArgumentTypeError(
                "sizes must be positive MiB values"
            )
        sizes.append(size)
    return sizes


class BenchError(RuntimeError):
    pass


class Target:
    def __init__(self, name, kind, path=None, opts=(), ssh_compress=False):
        self.name = name
        self.kind = kind
        self.path = path
        self.opts = tuple(opts)
        self.ssh_compress = ssh_compress


class Case:
    def __init__(self, name, direction, size_mib):
        self.name = name
        self.direction = direction
        self.size_mib = size_mib


class Bench:
    def __init__(self, args):
        self.args = args
        self.tmp = tempfile.TemporaryDirectory(prefix="knc-throughput-bench.")
        self.tmpdir = self.tmp.name
        self.keytab = os.path.join(self.tmpdir, "server.keytab")
        self.ccache = os.path.join(self.tmpdir, "client.ccache")
        self.krb5_conf = os.path.join(self.tmpdir, "krb5.conf")
        self.marker_count = 0

    def close(self):
        self.tmp.cleanup()

    def setup(self):
        for tool in ("dd", "ktutil", "kimpersonate"):
            if shutil.which(tool) is None:
                raise BenchError("%s not found" % tool)
        if "ssh" in self.args.targets or "ssh-C" in self.args.targets:
            if shutil.which("ssh") is None:
                raise BenchError("ssh not found")
        if not os.path.exists(self.args.benchio):
            raise BenchError("benchio not found: %s" % self.args.benchio)
        if not os.access(self.args.benchio, os.X_OK):
            raise BenchError("benchio is not executable: %s" %
                             self.args.benchio)

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
            "ktutil", "-k", self.keytab, "add",
            "--principal=%s" % SERVER_PRINC,
            "--kvno=1",
            "--enctype=%s" % ENCTYPE,
            "--password=knc-throughput-bench-password",
        ], self.client_env())
        self.run_checked([
            "kimpersonate",
            "--krb5",
            "--client=%s" % CLIENT_PRINC,
            "--server=%s" % SERVER_PRINC,
            "--keytab=%s" % self.keytab,
            "--ccache=FILE:%s" % self.ccache,
            "--enc-type=%s" % ENCTYPE,
            "--session-enc-type=%s" % ENCTYPE,
        ], self.client_env())

    def run_checked(self, argv, env):
        proc = subprocess.run(
            argv,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            raise BenchError(
                "%s failed with %d\nstdout:\n%s\nstderr:\n%s" %
                (" ".join(argv), proc.returncode, proc.stdout, proc.stderr)
            )

    def base_env(self):
        env = os.environ.copy()
        env["KRB5_CONFIG"] = self.krb5_conf
        if self.args.libdir:
            old = env.get("LD_LIBRARY_PATH")
            env["LD_LIBRARY_PATH"] = self.args.libdir
            if old:
                env["LD_LIBRARY_PATH"] += ":" + old
        return env

    def server_env(self):
        env = self.base_env()
        env["KRB5_KTNAME"] = "FILE:%s" % self.keytab
        return env

    def client_env(self):
        env = self.base_env()
        env["KRB5CCNAME"] = "FILE:%s" % self.ccache
        return env

    def targets(self):
        targets = []
        for name in self.args.targets:
            if name == "old":
                targets.append(Target(name, "knc", self.args.old_knc))
            elif name == "new":
                targets.append(Target(name, "knc", self.args.new_knc))
            elif name == "new-lz4":
                targets.append(Target(
                    name, "knc", self.args.new_knc, ("-o", "lz4")))
            elif name == "ssh":
                targets.append(Target(name, "ssh", ssh_compress=False))
            elif name == "ssh-C":
                targets.append(Target(name, "ssh", ssh_compress=True))
            else:
                raise BenchError("unknown target: %s" % name)

        for target in targets:
            if target.kind == "knc":
                if not target.path or not os.path.exists(target.path):
                    raise BenchError(
                        "%s knc executable not found: %s" %
                        (target.name, target.path)
                    )
                if not os.access(target.path, os.X_OK):
                    raise BenchError(
                        "%s knc executable is not executable: %s" %
                        (target.name, target.path)
                    )
        return targets

    def cases(self):
        ret = []
        for size in self.args.sizes_mib:
            if "upload" in self.args.cases:
                ret.append(Case("upload-%dm" % size, "upload", size))
            if "download" in self.args.cases:
                ret.append(Case("download-%dm" % size, "download", size))
        return ret

    def bytes_for(self, case):
        return case.size_mib * MIB

    def marker_path(self, target, case):
        path = os.path.join(
            self.tmpdir,
            "%s.%s.%d.marker" %
            (target.name, case.name, self.marker_count),
        )
        self.marker_count += 1
        return path

    def validate_marker(self, path, case):
        try:
            with open(path, "r", encoding="utf-8") as f:
                got = int(f.read().strip())
        except OSError as e:
            raise BenchError("marker read failed for %s: %s" % (path, e))
        if got != self.bytes_for(case):
            raise BenchError(
                "marker mismatch for %s: got %d expected %d" %
                (case.name, got, self.bytes_for(case))
            )

    def free_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def start_knc_server(self, target, case, marker):
        port = self.free_port()
        if case.direction == "upload":
            command = [
                self.args.benchio, "sink", str(self.bytes_for(case)),
                marker,
            ]
        else:
            command = [
                self.args.benchio, "source", str(self.bytes_for(case)),
            ]

        argv = [
            target.path,
        ] + list(target.opts) + [
            "-l", "-f", "-M", "1", "-a", "127.0.0.1", str(port),
        ] + command

        proc = subprocess.Popen(
            argv,
            env=self.server_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.1)
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            raise BenchError(
                "%s server failed to start\nstderr:\n%s" %
                (target.name, show(stderr))
            )
        return proc, port

    def finish_knc_server(self, target, server):
        try:
            _, stderr = server.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            server.kill()
            _, stderr = server.communicate()
            raise BenchError(
                "%s server timed out\nstderr:\n%s" %
                (target.name, show(stderr))
            )
        if server.returncode not in (0, 1):
            raise BenchError(
                "%s server failed with %d\nstderr:\n%s" %
                (target.name, server.returncode, show(stderr))
            )

    def knc_client_argv(self, target, port):
        return [
            target.path,
        ] + list(target.opts) + [
            "host@127.0.0.1", str(port),
        ]

    def ssh_argv(self, target):
        argv = [
            "ssh", "-F", "/dev/null",
            "-p", str(self.args.ssh_port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=%s" % self.args.ssh_known_hosts,
            "-o", "LogLevel=ERROR",
        ]
        if self.args.ssh_key:
            argv += ["-i", self.args.ssh_key]
        if target.ssh_compress:
            argv.append("-C")
        else:
            argv += ["-o", "Compression=no"]
        argv.append(self.args.ssh_host)
        return argv

    def run_upload(self, argv, env=None, check_source=True):
        source = subprocess.Popen(
            [
                self.args.benchio, "source", str(self.bytes_for(
                    self.current_case)),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            proc = subprocess.Popen(
                argv,
                env=env,
                stdin=source.stdout,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            source.stdout.close()
            try:
                _, stderr = proc.communicate(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                source.kill()
                _, stderr = proc.communicate()
                raise BenchError(
                    "upload timed out\nstderr:\n%s" % show(stderr))
        finally:
            if source.stdout:
                source.stdout.close()
        source_stderr = source.communicate(timeout=TIMEOUT)[1]
        if proc.returncode != 0:
            raise BenchError("upload command failed with %d\nstderr:\n%s" %
                             (proc.returncode, show(stderr)))
        if check_source and source.returncode != 0:
            raise BenchError("benchio source failed with %d\nstderr:\n%s" %
                             (source.returncode, show(source_stderr)))
        if (not check_source and source.returncode not in
                (0, -signal.SIGPIPE)):
            raise BenchError("benchio source failed with %d\nstderr:\n%s" %
                             (source.returncode, show(source_stderr)))

    def run_download(self, argv, env=None, marker=None):
        sink = subprocess.Popen(
            [
                self.args.benchio, "sink",
                str(self.bytes_for(self.current_case)),
                marker,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        proc = subprocess.Popen(
            argv,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=sink.stdin,
            stderr=subprocess.PIPE,
        )
        sink.stdin.close()
        sink.stdin = None
        try:
            _, stderr = proc.communicate(timeout=TIMEOUT)
            sink_stderr = sink.communicate(timeout=TIMEOUT)[1]
        except subprocess.TimeoutExpired:
            proc.kill()
            sink.kill()
            _, stderr = proc.communicate()
            raise BenchError("download timed out\nstderr:\n%s" %
                             show(stderr))
        if proc.returncode != 0:
            raise BenchError("download command failed with %d\nstderr:\n%s" %
                             (proc.returncode, show(stderr)))
        if sink.returncode != 0:
            raise BenchError("benchio sink failed with %d\nstderr:\n%s" %
                             (sink.returncode, show(sink_stderr)))

    def run_knc_once(self, target, case):
        marker = self.marker_path(target, case)
        server, port = self.start_knc_server(target, case, marker)
        self.current_case = case
        start = time.perf_counter()
        try:
            if case.direction == "upload":
                self.run_upload(
                    self.knc_client_argv(target, port), self.client_env(),
                    check_source=False)
            else:
                self.run_download(
                    self.knc_client_argv(target, port), self.client_env(),
                    marker)
            self.finish_knc_server(target, server)
            self.validate_marker(marker, case)
            return time.perf_counter() - start
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()

    def run_ssh_once(self, target, case):
        self.current_case = case
        start = time.perf_counter()
        if case.direction == "upload":
            self.run_upload(
                self.ssh_argv(target) + [
                    "dd of=/dev/null bs=1M count=%d status=none" %
                    case.size_mib,
                ], check_source=False)
        else:
            marker = self.marker_path(target, case)
            self.run_download(
                self.ssh_argv(target) + [
                    "dd if=/dev/zero bs=1M count=%d status=none" %
                    case.size_mib,
                ], marker=marker)
            self.validate_marker(marker, case)
        return time.perf_counter() - start

    def run_once(self, target, case):
        if target.kind == "knc":
            return self.run_knc_once(target, case)
        return self.run_ssh_once(target, case)


def show(data):
    limit = 4096
    text = data[:limit].decode("utf-8", "replace")
    if len(data) > limit:
        text += "\n[truncated to %d of %d bytes]" % (limit, len(data))
    return text


def print_results(results, cases, targets):
    print("")
    print("%-14s %-10s %10s %10s %10s" %
          ("case", "target", "median-s", "min-s", "MiB/s"))
    print("%-14s %-10s %10s %10s %10s" %
          ("-" * 14, "-" * 10, "-" * 10, "-" * 10, "-" * 10))
    for case in cases:
        for target in targets:
            values = results[(case.name, target.name)]
            med = median(values)
            print("%-14s %-10s %10.4f %10.4f %10.2f" %
                  (case.name, target.name, med, min(values),
                   throughput(case.size_mib, med)))


def parse_args():
    top = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(
        description="Benchmark KNC throughput with system data pumps."
    )
    parser.add_argument(
        "--old-knc", default="/usr/local/bin/knc",
        help="old knc executable, default: /usr/local/bin/knc",
    )
    parser.add_argument(
        "--new-knc", default=os.path.join(top, "bin", ".libs", "knc"),
        help="new knc executable, default: ../bin/.libs/knc",
    )
    parser.add_argument(
        "--libdir", default=os.path.join(top, "lib", ".libs"),
        help="library directory to prepend to LD_LIBRARY_PATH",
    )
    parser.add_argument(
        "--benchio", default=os.path.join(top, "test", "benchio"),
        help="benchio helper path",
    )
    parser.add_argument(
        "--targets", type=parse_csv, default=parse_csv("new,new-lz4"),
        help="comma-separated targets: old,new,new-lz4,ssh,ssh-C",
    )
    parser.add_argument(
        "--cases", type=parse_csv, default=parse_csv("upload,download"),
        help="comma-separated cases: upload,download",
    )
    parser.add_argument(
        "--sizes-mib", type=parse_sizes_mib, default=parse_sizes_mib("16,256"),
        help="comma-separated MiB sizes",
    )
    parser.add_argument(
        "--iterations", type=int, default=5,
        help="measured iterations per case and target",
    )
    parser.add_argument(
        "--warmups", type=int, default=1,
        help="unmeasured warmups per case and target",
    )
    parser.add_argument("--ssh-host", default="root@127.0.0.1")
    parser.add_argument("--ssh-port", default=22)
    parser.add_argument("--ssh-key")
    parser.add_argument(
        "--ssh-known-hosts", default=os.path.expanduser("~/.ssh/known_hosts"))
    args = parser.parse_args()

    valid_targets = {"old", "new", "new-lz4", "ssh", "ssh-C"}
    unknown_targets = set(args.targets) - valid_targets
    if unknown_targets:
        raise SystemExit(
            "unknown targets: %s" % ",".join(sorted(unknown_targets)))

    valid_cases = {"upload", "download"}
    unknown_cases = set(args.cases) - valid_cases
    if unknown_cases:
        raise SystemExit(
            "unknown cases: %s" % ",".join(sorted(unknown_cases)))

    if args.iterations < 1:
        raise SystemExit("--iterations must be at least 1")
    if args.warmups < 0:
        raise SystemExit("--warmups must be non-negative")
    return args


def main():
    args = parse_args()
    bench = Bench(args)
    try:
        bench.setup()
        targets = bench.targets()
        cases = bench.cases()
        results = {}

        print("targets: %s" % ", ".join(t.name for t in targets))
        print("sizes MiB: %s" % ", ".join(str(s) for s in args.sizes_mib))
        print("iterations: %d, warmups: %d" %
              (args.iterations, args.warmups))

        for case in cases:
            print("case: %s" % case.name)
            for _ in range(args.warmups):
                for target in targets:
                    bench.run_once(target, case)

            for i in range(args.iterations):
                for target in targets:
                    elapsed = bench.run_once(target, case)
                    results.setdefault((case.name, target.name), []).append(
                        elapsed)
                    print("  %-10s iter %d: %.4fs" %
                          (target.name, i + 1, elapsed))

        print_results(results, cases, targets)
    finally:
        bench.close()


if __name__ == "__main__":
    sys.exit(main())
