"""Public source CLI and compatibility-routing adversarial tests."""
from __future__ import annotations

import contextlib
import io
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from test.quality.source_gate import cli


REPO_ROOT = Path(__file__).resolve().parents[2]


class SourceGateCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            dir=os.path.realpath(tempfile.gettempdir()),
        )
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _empty_root(self, name="output"):
        value = self.root / name
        value.mkdir(mode=0o700)
        os.chmod(value, 0o700)
        return value

    def test_01_public_argv_is_exact_and_has_no_subset_or_old_vocabulary(self):
        valid = str(self._empty_root())
        self.assertEqual(
            cli._parse(["run", "--output-root", valid]),
            valid,
        )
        for argv in (
            [],
            ["run"],
            ["run", "--output-root"],
            ["run", "--output-root=" + valid],
            ["run", "--output-root", valid, "--suite", "one"],
            ["run", "--output-root", valid, "--scenario", "pass"],
            ["run", "--require-release-ready"],
            ["--require-release-ready"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError):
                    cli._parse(argv)

    def test_02_output_root_must_be_external_empty_exact_0700_directory(self):
        valid = self._empty_root("valid")
        root, fd = cli._validate_output_root(str(valid))
        self.assertEqual(root, str(valid))
        os.close(fd)

        nonempty = self._empty_root("nonempty")
        (nonempty / "foreign").write_text("x")
        loose = self._empty_root("loose")
        os.chmod(loose, 0o755)
        target = self._empty_root("target")
        symlink = self.root / "symlink"
        symlink.symlink_to(target)
        for value in (
            "relative",
            "/",
            str(nonempty),
            str(loose),
            str(symlink),
            str(REPO_ROOT),
            str(REPO_ROOT / "inside"),
        ):
            with self.subTest(value=value):
                with self.assertRaises(cli.SourceCliPreflightError):
                    cli._validate_output_root(value)

    def test_03_private_executor_seam_receives_one_bound_root(self):
        output = self._empty_root()
        calls = []

        def fake(root, root_fd):
            calls.append((root, os.fstat(root_fd).st_ino))
            return 0, None

        self.assertEqual(
            cli._main(["run", "--output-root", str(output)], fake),
            0,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], str(output))
        self.assertEqual(list(output.iterdir()), [])

    def test_04_run_all_rejects_legacy_and_forwards_only_exact_cli(self):
        legacy = subprocess.run(
            ["/bin/bash", "test/run_all.sh", "--require-release-ready"],
            cwd=REPO_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(legacy.returncode, 64)

        sandbox = self.root / "copy"
        (sandbox / "test").mkdir(parents=True)
        source = (REPO_ROOT / "test/run_all.sh").read_text("utf-8")
        recorder = sandbox / "record"
        fake = sandbox / "fake-python"
        fake.write_text(
            "#!/bin/bash\n"
            "printf '%s\\n' \"$@\" > "
            + str(recorder)
            + "\n",
        )
        os.chmod(fake, 0o700)
        (sandbox / "test/run_all.sh").write_text(
            source.replace("/usr/bin/python3", str(fake)),
        )
        os.chmod(sandbox / "test/run_all.sh", 0o700)
        output = self._empty_root("forwarded")
        forwarded = subprocess.run(
            [
                "/bin/bash",
                str(sandbox / "test/run_all.sh"),
                "--output-root",
                str(output),
            ],
            cwd=REPO_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(forwarded.returncode, 0)
        self.assertEqual(
            recorder.read_text("utf-8").splitlines(),
            [
                "-I",
                "test/quality/source_gate/cli.py",
                "run",
                "--output-root",
                str(output),
            ],
        )

    def test_05_real_isolated_cli_rejects_invalid_argv_before_runtime(self):
        for argv in (
            ["--require-release-ready"],
            ["run", "--output-root=/private/tmp/forged"],
            ["run", "--output-root", "/private/tmp/x", "--suite", "one"],
        ):
            with self.subTest(argv=argv):
                result = subprocess.run(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "test/quality/source_gate/cli.py",
                        *argv,
                    ],
                    cwd=REPO_ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 64)

        alternate = Path(
            "/Applications/Xcode.app/Contents/Developer/Library/"
            "Frameworks/Python3.framework/Versions/3.9/Resources/"
            "Python.app/Contents/MacOS/Python",
        )
        output = self._empty_root("alternate-python")
        result = subprocess.run(
            [
                str(alternate),
                "-I",
                "test/quality/source_gate/cli.py",
                "run",
                "--output-root",
                str(output),
            ],
            cwd=REPO_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 12)
        self.assertEqual(list(output.iterdir()), [])

    def test_06_output_root_rebind_suppresses_stdout_claim(self):
        output = self._empty_root("rebound")
        moved = self.root / "moved"

        def rebind(root, root_fd):
            os.rename(root, moved)
            Path(root).mkdir(mode=0o700)
            os.chmod(root, 0o700)
            return 0, {
                "claim": "SOURCE-GREEN",
                "runner_exit": 0,
            }

        captured = io.BytesIO()

        class Stdout:
            buffer = captured

        with contextlib.redirect_stdout(io.StringIO()):
            # _main must reject before touching stdout.buffer.  The redirect is
            # intentionally ordinary text stdout; any attempted binary claim
            # would itself fail the test.
            self.assertEqual(
                cli._main(["run", "--output-root", str(output)], rebind),
                12,
            )
        self.assertEqual(captured.getvalue(), b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
