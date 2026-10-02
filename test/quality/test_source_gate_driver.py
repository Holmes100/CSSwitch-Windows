"""Private fake-only tests for the snapshot-bound gateway driver."""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from test.quality.run_evidence.attempt0_runner import supervise_raw_command
from test.quality.run_evidence.manifest_contracts import (
    canonical_json_bytes,
)
from test.quality.source_gate import gateway_driver


class GatewayDriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "gateway-target"
        self.target.mkdir(mode=0o700)
        self.target.chmod(0o700)
        self.environment = {
            "CARGO_HOME": str(self.root / "cargo-home"),
            "CARGO_NET_OFFLINE": "true",
            "HOME": str(self.root / "home"),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/fixed/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "RUSTC": "/fixed/bin/rustc",
            "RUSTUP_HOME": str(self.root / "rustup"),
            "TMPDIR": str(self.root / "tmp"),
        }
        self.config = {
            "schema": "gateway-driver-config.v1",
            "target_dir": str(self.target),
            "cargo_path": "/fixed/bin/cargo",
            "python_path": "/fixed/bin/python3",
            "environment": self.environment,
        }

    def test_happy_build_binds_binary_then_runs_fixed_loopback(self):
        calls = []
        emitted = []

        def run_child(argv, environment):
            calls.append((tuple(argv), dict(environment)))
            if len(calls) == 1:
                binary = self.target / "debug/csswitch-gateway"
                binary.parent.mkdir(mode=0o755)
                binary.write_bytes(b"current-source-gateway")
                binary.chmod(0o755)
                return 0
            self.assertEqual(
                environment["CSSWITCH_GATEWAY_BIN"],
                str(self.target / "debug/csswitch-gateway"),
            )
            return 0

        rc = gateway_driver.run_driver(
            self.config,
            run_child=run_child,
            emit=emitted.append,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            calls[0][0],
            (
                "/fixed/bin/cargo",
                "build",
                "--offline",
                "--locked",
                "--manifest-path",
                "desktop/gateway/Cargo.toml",
                "--bin",
                "csswitch-gateway",
                "--target-dir",
                str(self.target),
            ),
        )
        self.assertEqual(
            calls[1][0],
            (
                "/fixed/bin/python3",
                "-m",
                "unittest",
                "test.test_gateway_rust",
                "test.test_provider_mock_scenarios",
                "test.test_installed_provider_matrix",
                "-v",
            ),
        )
        self.assertEqual(
            emitted,
            [{
                "path": str(
                    self.target / "debug/csswitch-gateway",
                ),
                "mode": "0755",
                "size": len(b"current-source-gateway"),
                "sha256": hashlib.sha256(
                    b"current-source-gateway",
                ).hexdigest(),
            }],
        )

    def test_build_failure_has_no_test_no_derived_record_and_no_retry(self):
        calls = []
        emitted = []

        def run_child(argv, environment):
            calls.append((tuple(argv), dict(environment)))
            return 101

        rc = gateway_driver.run_driver(
            self.config,
            run_child=run_child,
            emit=emitted.append,
        )
        self.assertEqual(rc, 12)
        self.assertEqual(len(calls), 1)
        self.assertEqual(emitted, [])
        self.assertEqual(list(self.target.iterdir()), [])

    def test_private_target_rejects_preoccupied_stale_mode_and_symlink(self):
        for case in ("preoccupied", "mode", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                dir=os.path.realpath(tempfile.gettempdir()),
            ) as temp:
                root = Path(temp)
                real_target = root / "real-target"
                real_target.mkdir(mode=0o700)
                real_target.chmod(0o700)
                target = real_target
                if case == "preoccupied":
                    (
                        real_target / "debug"
                    ).mkdir(mode=0o755)
                    stale = (
                        real_target
                        / "debug/csswitch-gateway"
                    )
                    stale.write_bytes(b"stale")
                    stale.chmod(0o755)
                elif case == "mode":
                    real_target.chmod(0o755)
                else:
                    target = root / "gateway-target"
                    target.symlink_to(real_target, target_is_directory=True)
                config = {
                    **self.config,
                    "target_dir": str(target),
                }
                calls = []
                emitted = []
                with self.assertRaises(
                    gateway_driver.GatewayDriverError,
                ):
                    gateway_driver.run_driver(
                        config,
                        run_child=lambda argv, env: calls.append(argv),
                        emit=emitted.append,
                    )
                self.assertEqual(calls, [])
                self.assertEqual(emitted, [])

    def test_missing_build_output_and_test_failure_never_retry(self):
        emitted = []
        calls = []

        def missing_binary(argv, environment):
            calls.append(tuple(argv))
            return 0

        with self.assertRaises(gateway_driver.GatewayDriverError):
            gateway_driver.run_driver(
                self.config,
                run_child=missing_binary,
                emit=emitted.append,
            )
        self.assertEqual(len(calls), 1)
        self.assertEqual(emitted, [])

        calls.clear()

        def failing_test(argv, environment):
            calls.append(tuple(argv))
            if len(calls) == 1:
                binary = self.target / "debug/csswitch-gateway"
                binary.parent.mkdir(mode=0o755)
                binary.write_bytes(b"current-source-gateway")
                binary.chmod(0o755)
                return 0
            return 1

        rc = gateway_driver.run_driver(
            self.config,
            run_child=failing_test,
            emit=emitted.append,
        )
        self.assertEqual(rc, 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(emitted), 1)

    def test_outer_adapter_happy_path_frames_current_derived_record(self):
        fake_bin = self.root / "bin"
        fake_bin.mkdir(mode=0o755)
        cargo = fake_bin / "cargo"
        python = fake_bin / "python3"
        cargo.write_text(
            "#!/bin/bash\n"
            "[[ ! -e /dev/fd/198 ]] || exit 98\n"
            "target=\"${@: -1}\"\n"
            "mkdir -p \"$target/debug\"\n"
            "printf current-source-gateway >"
            " \"$target/debug/csswitch-gateway\"\n"
            "chmod 755 \"$target/debug/csswitch-gateway\"\n",
            encoding="utf-8",
        )
        python.write_text(
            "#!/bin/bash\n"
            "[[ ! -e /dev/fd/198 ]] || exit 98\n"
            "printf 'test_one (fake.Case) ... ok\\n'"
            " >&2\n"
            "printf '%s\\n' "
            "'----------------------------------------------------------------------'"
            " >&2\n"
            "printf 'Ran 1 test in 0.001s\\nOK\\n' >&2\n",
            encoding="utf-8",
        )
        cargo.chmod(0o755)
        python.chmod(0o755)
        environment = {
            **self.environment,
            "PATH": (
                str(fake_bin)
                + ":/usr/bin:/bin:/usr/sbin:/sbin"
            ),
        }
        driver_bootstrap = (
            "import os;"
            "os.lseek(195,0,0);"
            "p='/dev/fd/195';"
            "exec(compile(open(p,'rb').read(),p,'exec'))"
        )
        config = {
            "schema": "source-adapter-config.v1",
            "run_id": "0123456789abcdef0123456789abcdef",
            "suite_id": "SUITE-PY-LOOPBACK",
            "entrypoint_id": "ENTRY-SOURCE-PY-LOOPBACK",
            "kind": "python",
            "argv": [
                os.path.realpath(os.sys.executable),
                "-I",
                "-c",
                driver_bootstrap,
                "--config-fd",
                "197",
                "--derived-fd",
                "199",
            ],
            "environment": environment,
            "timeout_seconds": 10,
            "output_limit_bytes": 1024 * 1024,
            "expected_test_ids": ["fake.Case.test_one"],
            "approved_skipped_test_ids": [],
            "approved_ignored_test_ids": [],
            "approved_ignored_tests": {},
            "command_argv_sha256": "0" * 64,
            "environment_sha256": "0" * 64,
            "tool_identity_sha256": "0" * 64,
            "driver_config": {
                "schema": "gateway-driver-config.v1",
                "target_dir": str(self.target),
                "cargo_path": str(cargo),
                "python_path": str(python),
                "environment": environment,
            },
        }
        repo = Path(__file__).resolve().parents[2]
        adapter_fd = os.open(
            repo / "test/quality/source_gate/adapter.py",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        driver_fd = os.open(
            repo / "test/quality/source_gate/gateway_driver.py",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        self.addCleanup(os.close, adapter_fd)
        self.addCleanup(os.close, driver_fd)
        direct_target = self.root / "direct-gateway-target"
        direct_target.mkdir(mode=0o700)
        direct_target.chmod(0o700)
        direct_config = {
            **config["driver_config"],
            "target_dir": str(direct_target),
        }
        direct_raw = canonical_json_bytes(direct_config)
        direct_bootstrap = (
            "import os;"
            "os.lseek(198,0,0);"
            "p='/dev/fd/198';"
            "exec(compile(open(p,'rb').read(),p,'exec'))"
        )
        direct = supervise_raw_command(
            argv=(
                os.path.realpath(os.sys.executable),
                "-I",
                "-c",
                direct_bootstrap,
                "--config-fd",
                "197",
                "--derived-fd",
                "199",
            ),
            environment=environment,
            timeout_seconds=10,
            output_limit_bytes=1024 * 1024,
            framed_config=(
                len(direct_raw).to_bytes(4, "big") + direct_raw
            ),
            inherited_fds=((driver_fd, 198),),
        )
        self.assertEqual(
            direct.raw_process,
            {"state": "EXITED", "process_exit": 0},
            (
                direct.stdout,
                direct.stderr,
                direct.observation,
                direct.observation_error,
                direct.observation_acked,
            ),
        )
        self.assertIsNone(direct.observation_error)
        self.assertTrue(direct.observation_acked)
        raw = canonical_json_bytes(config)
        adapter_bootstrap = (
            "import os;"
            "os.lseek(198,0,0);"
            "p='/dev/fd/198';"
            "exec(compile(open(p,'rb').read(),p,'exec'))"
        )
        supervised = supervise_raw_command(
            argv=(
                os.path.realpath(os.sys.executable),
                "-I",
                "-c",
                adapter_bootstrap,
                "--config-fd",
                "197",
                "--observation-fd",
                "199",
            ),
            environment={
                "HOME": str(self.root),
                "PATH": os.defpath,
            },
            timeout_seconds=15,
            output_limit_bytes=1024 * 1024,
            framed_config=len(raw).to_bytes(4, "big") + raw,
            inherited_fds=((adapter_fd, 198), (driver_fd, 196)),
        )
        self.assertEqual(
            supervised.raw_process,
            {"state": "EXITED", "process_exit": 0},
            (
                supervised.stdout,
                supervised.stderr,
                supervised.observation,
                supervised.observation_error,
            ),
        )
        self.assertIsNone(supervised.observation_error)
        self.assertTrue(supervised.observation_acked)
        derived = supervised.observation["derived_tool"]
        self.assertEqual(
            derived["path"],
            str(self.target / "debug/csswitch-gateway"),
        )
        self.assertEqual(
            derived["sha256"],
            hashlib.sha256(b"current-source-gateway").hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
