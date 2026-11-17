"""Tests for the CLI entry point."""

import pytest

import secret_generator.cli as cli_module
from secret_generator.cli import main


def test_no_selection_is_usage_error(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.err


@pytest.mark.parametrize("count", ["0", "-1"])
def test_db_pass_invalid_count_is_usage_error(count, capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--db-pass", count])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.err


def test_jwt_hmac_only(capsys):
    assert main(["--jwt-hmac"]) == 0
    out = capsys.readouterr().out
    assert "=== JWT ===" in out
    assert "HMAC_SECRET" in out
    assert "DATABASE" not in out
    assert "APP_SECRETS" not in out


def test_jwt_rsa_only(capsys):
    assert main(["--jwt-rsa"]) == 0
    out = capsys.readouterr().out
    assert "RSA_PRIVATE_KEY" in out
    assert "RSA_PUBLIC_KEY" in out
    assert "HMAC_SECRET" not in out


def test_db_pass_explicit_count(capsys):
    assert main(["--db-pass", "3"]) == 0
    out = capsys.readouterr().out
    assert "=== DATABASE ===" in out
    assert "DB_PASSWORD_1" in out
    assert "DB_PASSWORD_2" in out
    assert "DB_PASSWORD_3" in out
    assert "DB_PASSWORD_4" not in out


def test_db_pass_without_count_defaults_to_two(capsys):
    assert main(["--db-pass"]) == 0
    out = capsys.readouterr().out
    assert "DB_PASSWORD_2" in out
    assert "DB_PASSWORD_3" not in out


def test_app_secrets_only(capsys):
    assert main(["--app-secrets"]) == 0
    out = capsys.readouterr().out
    assert "=== APP_SECRETS ===" in out
    assert "SECRET_KEY" in out
    assert "API_KEY" in out
    assert "=== JWT ===" not in out


def test_all_sections(capsys):
    assert main(["--all"]) == 0
    out = capsys.readouterr().out
    assert "=== JWT ===" in out
    assert "=== DATABASE ===" in out
    assert "=== APP_SECRETS ===" in out
    assert "HMAC_SECRET" in out
    assert "RSA_PRIVATE_KEY" in out
    assert "SECRET_KEY" in out


def test_all_generates_two_db_passwords_by_default(capsys):
    assert main(["--all"]) == 0
    out = capsys.readouterr().out
    assert "DB_PASSWORD_2" in out
    assert "DB_PASSWORD_3" not in out


def test_output_writes_file(capsys, tmp_path):
    target = tmp_path / "secrets.txt"
    assert main(["--jwt-hmac", "--output", str(target)]) == 0
    content = target.read_text()
    assert "WARNING: THESE ARE SENSITIVE CREDENTIALS" in content
    assert "HMAC_SECRET" in content
    assert "Секреты сохранены" in capsys.readouterr().out


def test_runtime_failure_returns_1(monkeypatch, capsys):
    def fail():
        raise RuntimeError("boom")

    monkeypatch.setattr(cli_module, "generate_rsa_key_pair", fail)
    assert main(["--jwt-rsa"]) == 1
    assert capsys.readouterr().err


def test_keyboard_interrupt_returns_130(monkeypatch):
    def interrupted():
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, "generate_rsa_key_pair", interrupted)
    assert main(["--jwt-rsa"]) == 130
