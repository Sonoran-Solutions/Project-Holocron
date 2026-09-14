"""Regression checks for the canonical retail bootstrap runner.

These tests exercise the runner's *control* logic only -- mode-variable
sanitization, time-bound arithmetic, verified restoration, and the refusal to
patch an unrecognized build. They never launch the isolated runtime and never
touch the Steam installation. Each test that patches anything operates on a
throwaway copy of the private client under a temporary directory.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
# The canonical runner's filename contains a hyphen, so it cannot be imported by
# name; load it from its path.
spec = importlib.util.spec_from_file_location(
    'run_retail_bootstrap_probe', ROOT / 'tools' / 'run-retail-bootstrap-probe.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

REAL_EXE = ROOT / '.local-test' / 'client-v1' / 'game' / 'swtor' / 'retailclient' / 'swtor.exe'
# Captured before any test monkey-patches the module attribute.
PACKAGED_CLIENT_SHA256 = runner.EXPECTED_CLIENT_SHA256


def _write_synthetic_client(directory: Path) -> Path:
    """Write a synthetic executable carrying the expected digest and immediate.

    The runner only cares about the file's sha256 and the six resolver bytes, so
    a tiny stand-in keeps these tests fast and independent of the multi-megabyte
    private client.
    """
    exe = directory / 'swtor.exe'
    body = bytearray(runner.FILE_OFFSET + 0x100)
    body[runner.FILE_OFFSET:runner.FILE_OFFSET + runner.INSTRUCTION_LENGTH] = runner.ORIGINAL
    exe.write_bytes(body)
    return exe


@contextlib.contextmanager
def _runner_paths(exe: Path, launcher: Path):
    """Point the runner's module-level paths at a temporary tree."""
    saved = (runner.EXE, runner.LAUNCHER, runner.EXPECTED_CLIENT_SHA256)
    runner.EXE = exe
    runner.LAUNCHER = launcher
    runner.EXPECTED_CLIENT_SHA256 = hashlib.sha256(exe.read_bytes()).hexdigest()
    try:
        yield
    finally:
        runner.EXE, runner.LAUNCHER, runner.EXPECTED_CLIENT_SHA256 = saved


@contextlib.contextmanager
def _argv(values):
    saved = sys.argv
    sys.argv = ['run-retail-bootstrap-probe.py'] + list(values)
    try:
        yield
    finally:
        sys.argv = saved


class ModeEnvironmentTests(unittest.TestCase):
    """`--no-bootstrap-probe` must win over an already-exported variable."""

    def test_every_documented_mode_variable_is_cleared(self):
        polluted = {
            'HOLOCRON_AUTH_CAPTURE': '1',
            'HOLOCRON_AUTH_LOGIN_REPLY': '1',
            'HOLOCRON_AUTH_ID_BOOTSTRAP': '1',
            'HOLOCRON_WINEDBG_GDB': '1',
            'HOLOCRON_WINEDBG_TRACE': '1',
            'HOLOCRON_GDB_PARENT': '1',
            'HOLOCRON_GDB_INNER': '1',
            'HOLOCRON_GDB_TRACE': '1',
            'HOLOCRON_DORMANT_DEBUG': '1',
            'HOLOCRON_WINEDEBUG': '-all',   # not a mode switch; must survive
            'PATH': '/usr/bin',
        }
        cleared = runner.sanitize_mode_environment(polluted)
        self.assertEqual(sorted(cleared), sorted(runner.MODE_ENVIRONMENT_VARIABLES))
        self.assertEqual(polluted, {'HOLOCRON_WINEDEBUG': '-all', 'PATH': '/usr/bin'})

    def test_no_bootstrap_probe_survives_an_inherited_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            exe = _write_synthetic_client(tmpdir)
            launcher = tmpdir / 'launcher.sh'
            # The stub launcher records the Holocron environment it was handed.
            record = tmpdir / 'env.json'
            launcher.write_text(
                '#!/usr/bin/env bash\n'
                f'python3 -c "import json,os;json.dump({{k:v for k,v in os.environ.items() '
                f'if k.startswith(\'HOLOCRON_\')}},open(r\'{record}\',\'w\'))"\n')
            launcher.chmod(0o755)

            inherited = {
                'HOLOCRON_AUTH_ID_BOOTSTRAP': '1',
                'HOLOCRON_AUTH_LOGIN_REPLY': '1',
                'HOLOCRON_GDB_TRACE': '1',
            }
            saved_environ = dict(os.environ)
            os.environ.clear()
            os.environ.update(saved_environ)
            os.environ.update(inherited)
            try:
                with _runner_paths(exe, launcher):
                    with _argv(['--no-bootstrap-probe', '--seconds', '1']):
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.assertEqual(runner.main(), 0)
            finally:
                os.environ.clear()
                os.environ.update(saved_environ)

            handed = json.loads(record.read_text())
            self.assertNotIn('HOLOCRON_AUTH_ID_BOOTSTRAP', handed,
                             '--no-bootstrap-probe must survive an inherited export')
            self.assertNotIn('HOLOCRON_AUTH_LOGIN_REPLY', handed)
            self.assertNotIn('HOLOCRON_GDB_TRACE', handed)

    def test_probe_mode_is_opt_in_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            exe = _write_synthetic_client(tmpdir)
            launcher = tmpdir / 'launcher.sh'
            record = tmpdir / 'env.txt'
            launcher.write_text(
                '#!/usr/bin/env bash\n'
                f'echo "${{HOLOCRON_AUTH_ID_BOOTSTRAP:-unset}}" > {record}\n')
            launcher.chmod(0o755)
            with _runner_paths(exe, launcher):
                with _argv(['--seconds', '1']):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(runner.main(), 0)
            self.assertEqual(record.read_text().strip(), '1')


class TimeBoundTests(unittest.TestCase):
    """`--seconds` must describe an actual bound, with no phantom variable."""

    def test_deadline_adds_the_fixed_grace_period(self):
        self.assertEqual(runner.launcher_deadline_seconds(240.0), 240.0 + runner.SHUTDOWN_GRACE_SECONDS)
        self.assertEqual(runner.launcher_deadline_seconds(0.0, grace=5.0), 5.0)

    def test_runner_no_longer_claims_an_unused_launcher_time_limit(self):
        # HOLOCRON_RUN_SECONDS was set by an earlier revision but read by nothing
        # in the launcher; a run could outlive --seconds with no visible signal.
        source = (ROOT / 'tools' / 'run-retail-bootstrap-probe.py').read_text()
        self.assertNotIn('HOLOCRON_RUN_SECONDS', source)
        launcher = (ROOT / 'tools' / 'launch-isolated-client.sh').read_text()
        self.assertNotIn('HOLOCRON_RUN_SECONDS', launcher)


class RestorationTests(unittest.TestCase):
    """Canonical runs must always leave the private executable restored."""

    def test_keep_patched_flag_is_gone(self):
        source = (ROOT / 'tools' / 'run-retail-bootstrap-probe.py').read_text()
        self.assertNotIn('--keep-patched', source)
        self.assertNotIn('keep_patched', source)

    def test_client_is_restored_byte_exactly_after_a_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            exe = _write_synthetic_client(tmpdir)
            launcher = tmpdir / 'launcher.sh'
            launcher.write_text('#!/usr/bin/env bash\nexit 0\n')
            launcher.chmod(0o755)
            before = exe.read_bytes()
            with _runner_paths(exe, launcher):
                with _argv(['--seconds', '1']):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(runner.main(), 0)
            self.assertEqual(exe.read_bytes(), before)

    def test_client_is_restored_even_when_the_launcher_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            exe = _write_synthetic_client(tmpdir)
            launcher = tmpdir / 'launcher.sh'
            launcher.write_text('#!/usr/bin/env bash\nexit 9\n')
            launcher.chmod(0o755)
            before = exe.read_bytes()
            with _runner_paths(exe, launcher):
                with _argv(['--seconds', '1']):
                    with contextlib.redirect_stdout(io.StringIO()):
                        runner.main()
            self.assertEqual(exe.read_bytes(), before)

    def test_unknown_build_is_refused_without_patching(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            exe = _write_synthetic_client(tmpdir)
            launcher = tmpdir / 'launcher.sh'
            launcher.write_text('#!/usr/bin/env bash\nexit 0\n')
            launcher.chmod(0o755)
            before = exe.read_bytes()
            with _runner_paths(exe, launcher):
                runner.EXPECTED_CLIENT_SHA256 = '0' * 64  # unrecognized digest
                with _argv(['--seconds', '1']):
                    with contextlib.redirect_stdout(io.StringIO()):
                        with contextlib.redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit) as raised:
                                runner.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(exe.read_bytes(), before)


@unittest.skipUnless(REAL_EXE.is_file(), 'prepared private client not present')
class RealClientGuardTests(unittest.TestCase):
    """The real private client must be recognized and restorable."""

    def test_real_client_matches_the_recorded_build(self):
        digest = hashlib.sha256(REAL_EXE.read_bytes()).hexdigest()
        self.assertEqual(digest, PACKAGED_CLIENT_SHA256)

    def test_real_client_carries_the_expected_resolver_immediate(self):
        data = REAL_EXE.read_bytes()
        self.assertEqual(
            data[runner.FILE_OFFSET:runner.FILE_OFFSET + runner.INSTRUCTION_LENGTH],
            runner.ORIGINAL)


class CanonicalRunnerGuardTests(unittest.TestCase):
    """The documented procedure must point at the canonical runner only."""

    def test_state_doc_documents_the_canonical_runner_and_no_override(self):
        state = (ROOT / 'docs' / 'CURRENT-RETAIL-STATE.md').read_text()
        # Collapse the document's hard wrapping before matching prose.
        flat = ' '.join(state.split())
        self.assertIn('tools/run-retail-bootstrap-probe.py', flat)
        self.assertIn('Do not hand-patch the executable.', flat)
        self.assertIn('imposes **no** time limit', flat)
        self.assertNotIn('--keep-patched', flat)

    def test_launcher_selects_modes_only_from_the_environment(self):
        # The runner sanitizes the environment; the launcher must therefore not
        # default any of those branches to "on".
        launcher = (ROOT / 'tools' / 'launch-isolated-client.sh').read_text()
        for name in runner.MODE_ENVIRONMENT_VARIABLES:
            if name == 'HOLOCRON_AUTH_CAPTURE':
                continue  # inline ${VAR:+flag} expansion, never a branch
            self.assertIn(name, launcher, f'{name} is not consulted by the launcher')


if __name__ == '__main__':
    unittest.main()
