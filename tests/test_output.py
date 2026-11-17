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


def test_save_to_file_directory_target_exits(tmp_path, capsys):
    target = tmp_path / "adir"
    target.mkdir()
    with pytest.raises(SystemExit) as exc_info:
        save_to_file("content", str(target))
    assert exc_info.value.code == 1
    assert "Ошибка при сохранении" in capsys.readouterr().err
