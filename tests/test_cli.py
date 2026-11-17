"""Tests for the CLI entry point (current behavior)."""

import sys

import pytest

from secret_generator.cli import main


def run_cli(monkeypatch, *argv):
    """Run the CLI with the given arguments (output goes to capsys)."""
    monkeypatch.setattr(sys, "argv", ["secret-generator", *argv])
    main()


def test_no_selection_exits_with_hint(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["secret-generator"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Не выбраны опции генерации" in captured.out


def test_jwt_hmac_only(monkeypatch, capsys):
    run_cli(monkeypatch, "--jwt-hmac")
    out = capsys.readouterr().out
    assert "=== JWT ===" in out
    assert "HMAC_SECRET" in out
    assert "DATABASE" not in out
    assert "APP_SECRETS" not in out


def test_jwt_rsa_only(monkeypatch, capsys):
    run_cli(monkeypatch, "--jwt-rsa")
    out = capsys.readouterr().out
    assert "RSA_PRIVATE_KEY" in out
    assert "RSA_PUBLIC_KEY" in out
    assert "HMAC_SECRET" not in out


def test_db_pass_only(monkeypatch, capsys):
    run_cli(monkeypatch, "--db-pass", "2")
    out = capsys.readouterr().out
    assert "=== DATABASE ===" in out
    assert "DB_PASSWORD_1" in out
    assert "DB_PASSWORD_2" in out
    assert "DB_PASSWORD_3" not in out


def test_app_secrets_only(monkeypatch, capsys):
    run_cli(monkeypatch, "--app-secrets")
    out = capsys.readouterr().out
    assert "=== APP_SECRETS ===" in out
    assert "SECRET_KEY" in out
    assert "API_KEY" in out
    assert "=== JWT ===" not in out


def test_all_sections(monkeypatch, capsys):
    run_cli(monkeypatch, "--all")
    out = capsys.readouterr().out
    assert "=== JWT ===" in out
    assert "=== DATABASE ===" in out
    assert "=== APP_SECRETS ===" in out
    assert "HMAC_SECRET" in out
    assert "RSA_PRIVATE_KEY" in out
    assert "SECRET_KEY" in out


def test_all_generates_two_db_passwords_by_default(monkeypatch, capsys):
    run_cli(monkeypatch, "--all")
    out = capsys.readouterr().out
    assert "DB_PASSWORD_2" in out
    assert "DB_PASSWORD_3" not in out


def test_output_writes_file(monkeypatch, capsys, tmp_path):
    target = tmp_path / "secrets.txt"
    run_cli(monkeypatch, "--jwt-hmac", "--output", str(target))
    content = target.read_text()
    assert "WARNING: THESE ARE SENSITIVE CREDENTIALS" in content
    assert "HMAC_SECRET" in content
    assert "Секреты сохранены" in capsys.readouterr().out
