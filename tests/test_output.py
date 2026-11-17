"""Tests for output formatting and file saving."""

import pytest

from secret_generator.output import format_output, save_to_file


def test_format_output_starts_with_warning_banner():
    formatted = format_output({"JWT": {"HMAC_SECRET": "abc"}})
    assert formatted.startswith("⚠️ WARNING: THESE ARE SENSITIVE CREDENTIALS ⚠️")
    assert "DO NOT COMMIT TO VCS" in formatted


def test_format_output_sections():
    formatted = format_output(
        {
            "JWT": {"HMAC_SECRET": "abc"},
            "DATABASE": {"DB_PASSWORD_1": "pw1"},
        }
    )
    assert "=== JWT ===" in formatted
    assert "=== DATABASE ===" in formatted
    assert "HMAC_SECRET:\nabc" in formatted
    assert "DB_PASSWORD_1:\npw1" in formatted


def test_save_to_file_writes_content(tmp_path, capsys):
    target = tmp_path / "out.txt"
    save_to_file("secret content", str(target))
    assert target.read_text() == "secret content"
    assert "Секреты сохранены" in capsys.readouterr().out


def test_save_to_file_sets_owner_only_permissions(tmp_path):
    target = tmp_path / "out.txt"
    save_to_file("content", str(target))
    assert target.stat().st_mode & 0o777 == 0o600


def test_save_to_file_refuses_existing_target(tmp_path):
    target = tmp_path / "out.txt"
    target.write_text("old secrets")
    with pytest.raises(FileExistsError):
        save_to_file("new secrets", str(target))
    assert target.read_text() == "old secrets"


def test_save_to_file_force_overwrites(tmp_path):
    target = tmp_path / "out.txt"
    target.write_text("old secrets")
    save_to_file("new secrets", str(target), force=True)
    assert target.read_text() == "new secrets"
    assert target.stat().st_mode & 0o777 == 0o600


def test_save_to_file_directory_target_raises(tmp_path):
    target = tmp_path / "adir"
    target.mkdir()
    # O_EXCL reports EEXIST on macOS and EISDIR on Linux; both are OSError.
    with pytest.raises(OSError):
        save_to_file("content", str(target))
