#!/usr/bin/env python3

import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NCHAT_BIN = REPO_ROOT / 'build' / 'bin' / 'nchat'
KEYFILE_MAGIC = 'format=enc-v1'

class TestFailure(Exception):
    pass

def run_nchat(args, input_text, env=None):
    cmd = [str(NCHAT_BIN)] + args
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        env=env,
        cwd=str(REPO_ROOT),
        check=False,
    )

def assert_exit_in(result, codes, label):
    if result.returncode not in codes:
        msg = (
            f"{label}: expected exit in {codes}, got {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
        raise TestFailure(msg)

def assert_in(haystack, needle, label):
    if needle not in haystack:
        msg = (
            f"{label}: expected to find {needle!r} in output\n"
            f"STDOUT:\n{haystack}"
        )
        raise TestFailure(msg)

def assert_key_encrypted(key_path, label):
    if not key_path.exists():
        raise TestFailure(f"{label}: expected key file at {key_path} to exist")
    first_line = key_path.read_text().splitlines()[0]
    if first_line != KEYFILE_MAGIC:
        raise TestFailure(
            f"{label}: expected encrypted key starting with '{KEYFILE_MAGIC}', got '{first_line}'"
        )

def assert_key_plain(key_path, label):
    if not key_path.exists():
        raise TestFailure(f"{label}: expected key file at {key_path} to exist")
    first_line = key_path.read_text().splitlines()[0]
    if first_line == KEYFILE_MAGIC:
        raise TestFailure(
            f"{label}: expected plain (hex) key, but file starts with '{KEYFILE_MAGIC}'"
        )

def main():
    if not NCHAT_BIN.exists():
        raise SystemExit(f"nchat binary not found at {NCHAT_BIN}. Build the project first.")

    base_env = os.environ.copy()
    base_env.pop('NCHAT_KEY_PASSPHRASE', None)

    with tempfile.TemporaryDirectory(prefix='nchat-test-') as tmpdir:
        base_dir = Path(tmpdir)
        confdir = base_dir / 'conf'
        key_path = confdir / 'cache.key'

        # Test 1: empty passphrase is rejected
        result = run_nchat(['-p', '-d', str(confdir)], "\n", env=base_env)
        assert_exit_in(result, {1}, 'empty passphrase rejection')
        assert_in(result.stdout, 'Passphrase cannot be empty.', 'empty passphrase message')

        # Test 2: set passphrase successfully
        passphrase = 'SecretPass123!'
        set_input = f"{passphrase}\n{passphrase}\n"
        result = run_nchat(['-p', '-d', str(confdir)], set_input, env=base_env)
        assert_exit_in(result, {0, 1}, 'passphrase set success')
        assert_in(result.stdout, 'Cache key passphrase set.', 'passphrase set message')
        assert_key_encrypted(key_path, 'encrypted key check')

        # Test 3: fail to change passphrase with wrong current value
        wrong_input = 'WrongPass\nNewPass\nNewPass\n'
        result = run_nchat(['-P', '-d', str(confdir)], wrong_input, env=base_env)
        assert_exit_in(result, {1}, 'change passphrase wrong current failure')
        assert_in(result.stdout, 'Failed to update cache key passphrase. Check log for details.',
                  'change passphrase failure message')
        assert_key_encrypted(key_path, 'key still encrypted after failed change')

        # Test 4: remove passphrase with correct current value
        remove_input = f"{passphrase}\n\n\n"
        result = run_nchat(['-P', '-d', str(confdir)], remove_input, env=base_env)
        assert_exit_in(result, {0}, 'remove passphrase success')
        assert_in(result.stdout, 'Cache key passphrase removed.', 'remove passphrase message')
        assert_key_plain(key_path, 'key plain after removal')

        # Test 5: set a new passphrase after removal
        passphrase2 = 'AnotherSecret456?'
        reset_input = f"{passphrase2}\n{passphrase2}\n"
        result = run_nchat(['-p', '-d', str(confdir)], reset_input, env=base_env)
        assert_exit_in(result, {0, 1}, 'passphrase reset success')
        assert_in(result.stdout, 'Cache key passphrase set.', 'passphrase reset message')
        assert_key_encrypted(key_path, 'encrypted key after reset')

    print('All passphrase flow tests passed.')

if __name__ == '__main__':
    try:
        main()
    except TestFailure as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
