"""Dirty-tree-safe E2E tests for the fixed NODE-RUN-EVIDENCE CLI."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[2]
CLI = "test/quality/run_evidence/cli.py"
FIXTURE = "test/quality/fixtures/run_evidence/attempt0_fixture.py"
ALLOWLIST = (
    "quality/release-gates.v1.json",
    "quality/test-catalog.v1.json",
    "quality/schema/adapter-result.v1.schema.json",
    "quality/schema/change-set.v1.schema.json",
    "quality/schema/completion-seal.v1.schema.json",
    "quality/schema/evidence-manifest.v1.schema.json",
    "quality/schema/quality-kernel.v1.schema.json",
    "quality/schema/release-candidate.v1.schema.json",
    "quality/schema/run-failure.v1.schema.json",
    "quality/schema/run-manifest.v1.schema.json",
    "quality/schema/source-snapshot-manifest.v1.schema.json",
    "quality/schema/test-result.v1.schema.json",
    FIXTURE,
    "test/quality/run_evidence/aggregation_runner.py",
    "test/quality/run_evidence/atomic_store.py",
    "test/quality/run_evidence/attempt0_runner.py",
    "test/quality/run_evidence/clean_commit_snapshot.py",
    CLI,
    "test/quality/run_evidence/contracts.py",
    "test/quality/run_evidence/manifest_contracts.py",
    "test/quality/run_evidence/retry_runner.py",
)
VARIANT_HASHES = {
    "normal": "504713d3912381f98d54f0e18dc02ee19f8d72d04702e5b6509213db6fa95142",
    "fake-marker": "0fa248555ff05820cf944e24400b2e45a48c2475c0bcd63bd6aa87fb4e3e85d8",
    "readiness-pass": "0e0af27db2155b009a40fc95d61d0a19e5b3e13fe634e1efb250700dcc9e7fb7",
    "ignored": "d42e46e4e831d2ada9bdc5a11e9dc5ccedf854aea3b58a4114353f718a6db906",
    "test-fail": "a2303dfcaa2f3701a14eb0f16b78f12947a29ab5ce6275f58bc032277844eeb5",
    "env": "04dac753d34f9da4ca6bbbb9c13923b68509a4194eb0810e1fc9d85dd826a432",
    "real": "8f4b19ed8f8053a6b8fe5b903cb3535bbdf93cd6dc1e7b05291ea6d188bfc188",
    "skipped": "f8993622b06215c2cff1a194e19a2e667d9b5648d3076d707d734e96245aac2d",
    "missing": "0275defab7a139f66537d6a5aa5a02ecfa717b6229d41e2ca684542f18ec1f21",
    "malformed": "134a38d02456e01349b1251f445abbe530f2397118ef584ac93b0a3eac9cb742",
    "extra": "ed5eba81ddc17bc8fbb69b3958eb7c3859cb97d5ee956ecb3932b665248e6303",
    "timeout": "845c2742a0519313b7bea92117f618c4bcf36af7465919387fb207e46eaa0673",
    "readiness": "d68b58884e63423f7733939dfd1de089f95f02e5d296e4c79c649f677dd82e64",
    "input-drift": "2f3c43f3fad27a889b2f1e18591932f36fe8a202d63ed24c54814b9f5f213e18",
}
CLI_VARIANT_HASHES = {
    "output-root-rebind-after-seal": "de1d4a6a6b17c9111354d417da5f5e99d38102e39a8fa9a211a7571a24680a32",
    "post-seal-public-fd-close-oserror": "dbbb948ba4b96cc0cd19f491848c8a436fa268f968c45fee6dc966d55801ea11",
    "post-seal-root-close-oserror": "fa36a344c4e6b24e7c409c2cdd58ff1bbcf0d9c4a163bc93c6043b8e97b18794",
    "sys-executable-drift": "9a997a026fea5d4ad98cb077ba409c98c05285cf14c9b385783a03fb0b058ed1",
}
SCENARIOS = {
    "normal": b'"normal"',
    "fake-marker": b'"fake-marker"',
    "readiness-pass": b'"readiness" if attempt_index == 0 else "normal"',
    "ignored": b'"ignored"',
    "test-fail": b'"test-fail"',
    "env": b'"env"',
    "real": b'"real"',
    "skipped": b'"skipped"',
    "missing": b'"missing"',
    "malformed": b'"malformed"',
    "extra": b'"extra"',
    "timeout": b'"timeout"',
    "readiness": b'"readiness"',
}


class RunEvidenceCliE2E(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        )
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir(mode=0o700)
        self.home = self.base / "home"
        self.home.mkdir(mode=0o700)
        self.pycache = self.base / "pycache"
        self.pycache.mkdir(mode=0o700)
        self.outputs = 0
        for relative in ALLOWLIST:
            self._copy_exact(relative)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "RUE E2E")
        self.git("config", "user.email", "rue-e2e.invalid@example.invalid")
        self.git("add", "--", *ALLOWLIST)
        self.git("commit", "-m", "fixed e2e repository")
        self.git(
            "update-ref",
            "refs/remotes/origin/main",
            self.git("rev-parse", "HEAD").stdout.strip(),
        )
        tracked = tuple(
            item
            for item in self.git("ls-files", "-z").stdout.split("\0")
            if item
        )
        self.assertEqual(tracked, tuple(sorted(ALLOWLIST)))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _copy_exact(self, relative: str) -> None:
        source = SOURCE_ROOT / relative
        target = self.repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        source_fd = target_fd = None
        try:
            source_fd = os.open(
                source,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            before = os.fstat(source_fd)
            named = os.stat(source, follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(before.st_mode))
            self.assertEqual(before.st_nlink, 1)
            self.assertEqual(
                (before.st_dev, before.st_ino, before.st_size),
                (named.st_dev, named.st_ino, named.st_size),
            )
            raw = b""
            while len(raw) < before.st_size:
                chunk = os.read(source_fd, before.st_size - len(raw))
                self.assertTrue(chunk)
                raw += chunk
            self.assertFalse(os.read(source_fd, 1))
            after = os.fstat(source_fd)
            self.assertEqual(
                (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ),
                (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ),
            )
            target_fd = os.open(
                target,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                stat.S_IMODE(before.st_mode),
            )
            self.assertEqual(os.write(target_fd, raw), len(raw))
            os.fsync(target_fd)
            copied = os.fstat(target_fd)
            self.assertEqual(copied.st_size, len(raw))
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                hashlib.sha256((self.repo / relative).read_bytes()).hexdigest(),
            )
        finally:
            for fd in (target_fd, source_fd):
                if fd is not None:
                    os.close(fd)

    def git(self, *argv: str) -> subprocess.CompletedProcess:
        result = subprocess.run(
            ["/usr/bin/git", *argv],
            cwd=self.repo,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={
                "HOME": str(self.home),
                "PATH": os.defpath,
                "LANG": "C",
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def fixture_variant(self, name: str) -> None:
        raw = (SOURCE_ROOT / FIXTURE).read_bytes()
        needle = (
            b'scenario = os.environ.get('
            b'"RUE05A_PRIVATE_SCENARIO", "normal")'
        )
        self.assertEqual(raw.count(needle), 1)
        raw = raw.replace(needle, b"scenario = " + SCENARIOS.get(name, b'"normal"'))
        if name == "input-drift":
            old = b"        return rc if _recv_ack(peer) else 66"
            new = b"""        ack = _recv_ack(peer)
        if ack:
            child = os.fork()
            if child == 0:
                time.sleep(0.05)
                with open("quality/test-catalog.v1.json", "ab") as target:
                    target.write(b"\\n")
                os._exit(0)
        return rc if ack else 66"""
            self.assertEqual(raw.count(old), 1)
            raw = raw.replace(old, new)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), VARIANT_HASHES[name])
        path = self.repo / FIXTURE
        fd = os.open(
            path,
            os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            self.assertEqual(os.write(fd, raw), len(raw))
            os.fsync(fd)
        finally:
            os.close(fd)
        self.git("add", "--", FIXTURE)
        self.git("commit", "-m", "fixture " + name)
        self.git(
            "update-ref",
            "refs/remotes/origin/main",
            self.git("rev-parse", "HEAD").stdout.strip(),
        )

    def cli_variant(self, name: str) -> None:
        raw = (SOURCE_ROOT / CLI).read_bytes()
        if name == "output-root-rebind-after-seal":
            old = b"        seal = complete_fixed_run(layout, _now())\n"
            new = b"""        seal = complete_fixed_run(layout, _now())
        detached_root = root + ".detached"
        os.rename(root, detached_root)
        os.mkdir(root, 0o700)
"""
            self.assertEqual(raw.count(old), 1)
            raw = raw.replace(old, new)
        elif name == "post-seal-public-fd-close-oserror":
            old = b"""        _assert_output_root_binding(root, root_fd, expected_nlink=4)
        line = {
"""
            new = b"""        original_close = os.close

        def close_then_raise(fd: int) -> None:
            original_close(fd)
            raise OSError("injected public fd close failure")

        os.close = close_then_raise
        try:
            _assert_output_root_binding(root, root_fd, expected_nlink=4)
        finally:
            os.close = original_close
        line = {
"""
            self.assertEqual(raw.count(old), 1)
            raw = raw.replace(old, new)
        elif name == "post-seal-root-close-oserror":
            old = b'        line = {\n'
            new = b"""        os.close(root_fd)
        root_fd = -1
        line = {
"""
            self.assertEqual(raw.count(old), 1)
            raw = raw.replace(old, new)
        elif name == "sys-executable-drift":
            old = b"""        digests = _input_digests(
            capture.manifest,
            catalog_raw,
            gates_raw,
            layout,
            git_binding,
        )
"""
            new = old + b'        sys.executable = sys.executable + ".drift"\n'
            self.assertEqual(raw.count(old), 1)
            raw = raw.replace(old, new)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            CLI_VARIANT_HASHES[name],
        )
        path = self.repo / CLI
        fd = os.open(
            path,
            os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            self.assertEqual(os.write(fd, raw), len(raw))
            os.fsync(fd)
        finally:
            os.close(fd)
        self.git("add", "--", CLI)
        self.git("commit", "-m", "cli " + name)
        self.git(
            "update-ref",
            "refs/remotes/origin/main",
            self.git("rev-parse", "HEAD").stdout.strip(),
        )

    def new_output(self) -> Path:
        self.outputs += 1
        path = self.base / "output-{}".format(self.outputs)
        path.mkdir(mode=0o700)
        return path

    def run_raw(self, argv: list[str]) -> subprocess.CompletedProcess:
        env = {
            "HOME": str(self.home),
            "PATH": os.defpath,
            "LANG": "C",
            "LC_ALL": "C",
            "TMPDIR": str(self.base),
            "PYTHONPYCACHEPREFIX": str(self.pycache),
            "CSSWITCH_LOOPBACK_TEST_CMD": "printf PASS; exit 0",
            "RUE05A_PRIVATE_SCENARIO": "normal",
            "RUE_SCENARIO": "normal",
        }
        return subprocess.run(
            argv,
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=30,
        )

    def run_cli(self) -> tuple[subprocess.CompletedProcess, Path]:
        output = self.new_output()
        result = self.run_raw(
            [
                "/usr/bin/python3",
                "-I",
                CLI,
                "run",
                "--output-root",
                str(output),
            ],
        )
        return result, output

    def assert_sealed(
        self,
        result: subprocess.CompletedProcess,
        rc: int,
        decision: str,
    ) -> dict:
        self.assertEqual(result.returncode, rc, result.stderr.decode())
        line = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual(
            result.stdout,
            json.dumps(
                line,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            + b"\n",
        )
        self.assertEqual(line["claim"], "NODE-RUN-EVIDENCE")
        self.assertEqual(
            line["scope"],
            "fixed-one-suite-focused-source-unit",
        )
        self.assertEqual((line["decision"], line["runner_exit"]), (decision, rc))
        evidence = Path(line["evidence_path"])
        seal = json.loads((evidence / "completion-seal.json").read_text())
        result_value = json.loads(
            (evidence / "results/SUITE-RUE05A.json").read_text(),
        )
        self.assertEqual(
            (seal["aggregate_decision"], seal["runner_exit"]),
            (decision, rc),
        )
        self.assertEqual(
            (result_value["gate_decision"], result_value["runner_exit"]),
            (decision, rc),
        )
        self.assertEqual(line["run_id"], seal["run_id"])
        return result_value

    def test_happy_path_ignores_ambient_spoofing(self) -> None:
        self.fixture_variant("normal")
        result, _ = self.run_cli()
        value = self.assert_sealed(result, 0, "PASS")
        self.assertEqual(value["kind"], "PASS")

    def test_pass_marker_with_rc7_cannot_false_green(self) -> None:
        self.fixture_variant("fake-marker")
        result, _ = self.run_cli()
        value = self.assert_sealed(result, 12, "FAIL")
        self.assertEqual(value["kind"], "INFRA")

    def test_retry_and_blocked_outcomes(self) -> None:
        for scenario, expected_kind, expected_rc in (
            ("readiness-pass", "FLAKY_RETRY", 11),
            ("readiness", "READINESS_EXHAUSTED", 13),
            ("ignored", "IGNORED", 11),
            ("env", "ENV", 11),
            ("real", "REAL", 11),
            ("skipped", "SKIPPED", 11),
        ):
            with self.subTest(scenario=scenario):
                self.fixture_variant(scenario)
                result, _ = self.run_cli()
                value = self.assert_sealed(result, expected_rc, "BLOCKED")
                self.assertEqual(value["kind"], expected_kind)

    def test_fail_hard_and_adapter_corruption(self) -> None:
        for scenario, expected_rc in (
            ("test-fail", 10),
            ("timeout", 13),
            ("missing", 12),
            ("malformed", 12),
            ("extra", 12),
        ):
            with self.subTest(scenario=scenario):
                self.fixture_variant(scenario)
                result, _ = self.run_cli()
                self.assert_sealed(result, expected_rc, "FAIL")

    def test_catalog_drift_and_preoccupied_output_fail_preflight(self) -> None:
        catalog = self.repo / "quality/test-catalog.v1.json"
        catalog.write_bytes(catalog.read_bytes() + b"\n")
        output = self.new_output()
        result = self.run_raw(
            [
                "/usr/bin/python3",
                "-I",
                CLI,
                "run",
                "--output-root",
                str(output),
            ],
        )
        self.assertEqual((result.returncode, result.stdout), (2, b""))
        self.assertEqual(list(output.iterdir()), [])

        output2 = self.new_output()
        marker = output2 / "result.json"
        marker.write_bytes(b"occupied")
        result = self.run_raw(
            [
                "/usr/bin/python3",
                "-I",
                CLI,
                "run",
                "--output-root",
                str(output2),
            ],
        )
        self.assertEqual((result.returncode, result.stdout), (2, b""))
        self.assertEqual(marker.read_bytes(), b"occupied")

    def test_isolated_mode_is_required_before_output_mutation(self) -> None:
        output = self.new_output()
        result = self.run_raw(
            [
                "/usr/bin/python3",
                CLI,
                "run",
                "--output-root",
                str(output),
            ],
        )
        self.assertEqual((result.returncode, result.stdout), (2, b""))
        self.assertEqual(list(output.iterdir()), [])

    def test_unknown_duplicate_and_replayed_output_are_rejected(self) -> None:
        output = self.new_output()
        for suffix in (
            ["unknown"],
            ["run", "--output-root", str(output), "--output-root", str(output)],
        ):
            result = self.run_raw(["/usr/bin/python3", "-I", CLI, *suffix])
            self.assertEqual((result.returncode, result.stdout), (64, b""))
            self.assertEqual(list(output.iterdir()), [])
        self.fixture_variant("normal")
        result = self.run_raw(
            [
                "/usr/bin/python3",
                "-I",
                CLI,
                "run",
                "--output-root",
                str(output),
            ],
        )
        self.assert_sealed(result, 0, "PASS")
        replay = self.run_raw(
            [
                "/usr/bin/python3",
                "-I",
                CLI,
                "run",
                "--output-root",
                str(output),
            ],
        )
        self.assertEqual((replay.returncode, replay.stdout), (2, b""))

    def test_completion_input_drift_has_no_seal_or_stdout_claim(self) -> None:
        self.fixture_variant("input-drift")
        result, output = self.run_cli()
        self.assertEqual((result.returncode, result.stdout), (12, b""))
        self.assertFalse(any(output.glob("evidence/runs/*/completion-seal.json")))

    def test_output_root_rebind_after_seal_has_no_public_claim(self) -> None:
        self.fixture_variant("normal")
        self.cli_variant("output-root-rebind-after-seal")
        result, output = self.run_cli()
        self.assertEqual((result.returncode, result.stdout), (12, b""))
        self.assertEqual(list(output.iterdir()), [])
        self.assertFalse(any(output.glob("evidence/runs/*/completion-seal.json")))
        self.assertTrue(
            any(
                output.with_name(output.name + ".detached").glob(
                    "evidence/runs/*/completion-seal.json",
                ),
            ),
        )

    def test_post_seal_root_close_error_cannot_contradict_claim(self) -> None:
        self.fixture_variant("normal")
        self.cli_variant("post-seal-root-close-oserror")
        result, _ = self.run_cli()
        self.assert_sealed(result, 0, "PASS")

    def test_post_seal_public_fd_close_error_cannot_contradict_claim(self) -> None:
        self.fixture_variant("normal")
        self.cli_variant("post-seal-public-fd-close-oserror")
        result, _ = self.run_cli()
        self.assert_sealed(result, 0, "PASS")

    def test_tool_drift_after_capture_has_no_seal_or_stdout_claim(self) -> None:
        self.fixture_variant("normal")
        self.cli_variant("sys-executable-drift")
        result, output = self.run_cli()
        self.assertEqual((result.returncode, result.stdout), (12, b""))
        self.assertFalse(any(output.glob("evidence/runs/*/completion-seal.json")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
