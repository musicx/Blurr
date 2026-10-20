import os
from pathlib import Path
import subprocess
import sys

import pytest

from blurr import decrypt, encrypt
from blurr import cli

KEY = "cli 测试 key"


def call(*args):
    return cli.main(list(args))


def test_text_roundtrip(tmp_path):
    secret, restored = tmp_path / "secret.txt", tmp_path / "restored.txt"
    assert call("encrypt", "-t", "你好，世界 🌏", "-k", KEY, "-o", str(secret)) == 0
    assert secret.read_bytes().isascii()
    assert b"\n" not in secret.read_bytes()
    assert call("decrypt", "-i", str(secret), "-k", KEY, "-o", str(restored)) == 0
    assert restored.read_bytes() == "你好，世界 🌏".encode()
    if os.name == "posix":
        assert restored.stat().st_mode & 0o777 == 0o600


def test_file_roundtrip_and_explicit_text_encoding(tmp_path):
    source, secret, restored = (tmp_path / name for name in ("original", "secret", "restored"))
    original = "中文\r\nEnglish".encode("gb18030")
    source.write_bytes(original)
    assert call("encrypt", "-i", str(source), "-k", KEY, "-o", str(secret)) == 0
    assert call("decrypt", "-i", str(secret), "-k", KEY, "-o", str(restored)) == 0
    assert restored.read_bytes() == original
    assert source.read_bytes() == original
    assert call("encrypt", "-t", "中文", "--encoding", "gbk", "-k", KEY, "-o", str(secret), "--force") == 0
    assert decrypt(secret.read_text(), KEY) == "中文".encode("gbk")


def test_decrypt_literal_ciphertext(tmp_path):
    output = tmp_path / "plain"
    assert call("decrypt", "-t", encrypt(b"hello", KEY), "-k", KEY, "-o", str(output)) == 0
    assert output.read_bytes() == b"hello"


@pytest.mark.parametrize("exists", [False, True])
def test_failed_authentication_never_publishes_output(tmp_path, exists, capsys):
    secret, output = tmp_path / "secret", tmp_path / "plain"
    secret.write_text(encrypt(b"private", KEY))
    if exists:
        output.write_bytes(b"keep me")
    assert call("decrypt", "-i", str(secret), "-k", "wrong", "-o", str(output), "--force") == 1
    assert "incorrect key or damaged" in capsys.readouterr().err
    if exists:
        assert output.read_bytes() == b"keep me"
    else:
        assert not output.exists()
    assert not list(tmp_path.glob(".blurr-*"))


def test_no_clobber_and_force(tmp_path):
    output = tmp_path / "out"
    output.write_bytes(b"keep")
    args = ("encrypt", "-t", "new", "-k", KEY, "-o", str(output))
    assert call(*args) == 1
    assert output.read_bytes() == b"keep"
    assert call(*args, "--force") == 0
    assert decrypt(output.read_text(), KEY) == b"new"


@pytest.mark.parametrize("alias", ["same", "symlink", "hardlink"])
def test_source_cannot_be_overwritten_even_with_force(tmp_path, alias):
    source, output = tmp_path / "source", tmp_path / "output"
    source.write_bytes(b"original")
    if alias == "same":
        output = source
    elif alias == "symlink":
        output.symlink_to(source)
    else:
        os.link(source, output)
    assert call("encrypt", "-i", str(source), "-k", KEY, "-o", str(output), "--force") == 1
    assert source.read_bytes() == b"original"


@pytest.mark.parametrize("encoding", ["nonexistent-encoding", "ascii"])
def test_invalid_text_encoding_does_not_write(tmp_path, encoding):
    output = tmp_path / "out"
    assert call("encrypt", "-t", "中文", "--encoding", encoding, "-k", KEY, "-o", str(output)) == 1
    assert not output.exists()


def test_encoding_option_rejected_for_file(tmp_path):
    with pytest.raises(SystemExit) as exc:
        call("encrypt", "-i", "input.txt", "--encoding", "gbk", "-k", KEY, "-o", str(tmp_path / "out"))
    assert exc.value.code == 2


def test_key_environment(tmp_path, monkeypatch):
    output = tmp_path / "out"
    monkeypatch.setenv("BLURR_TEST_KEY", KEY)
    assert call("encrypt", "-t", "hello", "--key-env", "BLURR_TEST_KEY", "-o", str(output)) == 0
    assert decrypt(output.read_text(), KEY) == b"hello"


@pytest.mark.parametrize("value", [None, ""])
def test_missing_or_empty_key_environment(tmp_path, monkeypatch, value):
    monkeypatch.delenv("BLURR_TEST_KEY", raising=False)
    if value is not None:
        monkeypatch.setenv("BLURR_TEST_KEY", value)
    output = tmp_path / "out"
    assert call("encrypt", "-t", "hello", "--key-env", "BLURR_TEST_KEY", "-o", str(output)) == 1
    assert not output.exists()


@pytest.mark.parametrize("keys,expected", [([KEY, KEY], 0), ([KEY, "other"], 1), (["", ""], 1)])
def test_interactive_key_confirmation(tmp_path, monkeypatch, keys, expected):
    responses = iter(keys)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(responses))
    output = tmp_path / "out"
    assert call("encrypt", "-t", "hello", "-o", str(output)) == expected
    assert output.exists() == (expected == 0)


def test_stdin_and_installed_entrypoints(tmp_path):
    secret, restored = tmp_path / "secret", tmp_path / "restored"
    env = dict(os.environ, BLURR_TEST_KEY=KEY)
    args = ["encrypt", "-i", "-", "--key-env", "BLURR_TEST_KEY", "-o", str(secret)]
    result = subprocess.run([sys.executable, "-m", "blurr", *args], input="中文\r\n".encode("utf-16"), capture_output=True, env=env)
    assert result.returncode == 0, result.stderr
    assert result.stdout == b""
    result = subprocess.run([str(Path(sys.executable).parent / "blurr"), "decrypt", "-i", "-", "--key-env", "BLURR_TEST_KEY", "-o", str(restored)], input=secret.read_bytes(), capture_output=True, env=env)
    assert result.returncode == 0, result.stderr
    assert restored.read_bytes() == "中文\r\n".encode("utf-16")


def test_noninteractive_prompt_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert call("encrypt", "-t", "hello", "-o", str(tmp_path / "out")) == 1


def test_output_publication_race_preserves_existing_file(tmp_path, monkeypatch):
    output = tmp_path / "out"
    def race(source, destination):
        output.write_bytes(b"other process")
        raise FileExistsError("Destination exists")
    monkeypatch.setattr(cli.os, "link", race)
    with pytest.raises(FileExistsError):
        cli._write_output(output, b"new", False)
    assert output.read_bytes() == b"other process"
    assert not list(tmp_path.glob(".blurr-*"))


def test_failed_write_cleans_temporary_and_preserves_destination(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.write_bytes(b"keep")
    def fail(*args):
        raise OSError("simulated fsync failure")
    monkeypatch.setattr(cli.os, "fsync", fail)
    with pytest.raises(OSError):
        cli._write_output(output, b"new", True)
    assert output.read_bytes() == b"keep"
    assert not list(tmp_path.glob(".blurr-*"))


def test_missing_input_and_output_directory(tmp_path):
    assert call("encrypt", "-i", str(tmp_path / "missing"), "-k", KEY, "-o", str(tmp_path / "out")) == 1
    assert call("encrypt", "-t", "hello", "-k", KEY, "-o", str(tmp_path), "--force") == 1
    assert not list(tmp_path.glob(".blurr-*"))
