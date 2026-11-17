# Proposal

## Why

The project is a single-file Python script with dead packaging (`setup.py` is fully commented out), no lockfile, Russian-only docs and CLI output in a public repository, weak tests, no CI, and deprecated `cryptography` usage. It needs modernization before it can be reliably developed, reviewed, and extended.

## What Changes

- **Migrate to uv**: replace `requirements.txt` + dead `setup.py` with `pyproject.toml` (`cryptography` runtime dep, `pytest` + `ruff` dev deps), lock with `uv.lock`, console entry point, `--python >=3.10`.
- **Restructure into a package**: `src/main.py` monolith becomes `src/secret_generator/` (`generators.py`, `cli.py`, `output.py`) with a clean separation between pure generation logic and CLI/IO. **BREAKING**: `python3 src/main.py` no longer works; use `uv run secret-generator` or `python -m secret_generator`.
- **Fix code-level issues**:
  - Drop deprecated `default_backend` argument.
  - Emit RSA private keys in PKCS#8 (`BEGIN PRIVATE KEY`) instead of PKCS#1. **BREAKING**.
  - Library functions no longer call `sys.exit()`; errors are raised as exceptions, CLI converts them to exit codes.
  - `--db-pass 0` / negative values are rejected with a clear error instead of silently generating 2 passwords; `--db-pass` without `--all`/other flags now generates passwords.
  - Output file is written with `0600` permissions and refuses to overwrite an existing file unless `--force` is given.
  - Single shared password alphabet constant instead of two copies.
  - Running with no selection flags becomes a usage error (exit code 2 with a hint) instead of silent success (exit 0). **BREAKING**.
- **Tests**: migrate `unittest` → `pytest`; expand coverage to generators (round-trip RSA load, complexity, uniqueness), CLI (`capsys`, `tmp_path`), and output formatting. **BREAKING**: `python -m unittest discover tests` replaced by `pytest`.
- **English-only docs and UX**: translate README.md, all docstrings, CLI messages, and `.gitignore` comments to English. **BREAKING**: CLI output language changes from Russian to English.
- **CI and workflow**: GitHub Actions (ruff check/format + pytest across Python versions), gitflow with a long-lived `dev` branch, small feature-branch PRs targeting `dev`.

## Capabilities

### New Capabilities

- `secret-generation`: core generation behavior — JWT HMAC secrets, RSA key pairs (PKCS#8), DB passwords with complexity guarantees, app secrets; purity of library functions and error signaling via exceptions.
- `cli-interface`: CLI arguments, output format, exit codes, secure file saving (0600, no silent overwrite), English user-facing messages.
- `project-tooling`: uv-managed packaging (`pyproject.toml`, `uv.lock`), console entry point, Python version support, ruff lint/format, package layout.
- `test-suite`: pytest-based test suite — what must be covered (generators, CLI, output), no `unittest` legacy.
- `ci-pipeline`: GitHub Actions CI checks and the gitflow branch/PR conventions (`dev` as integration branch, small targeted PRs).
- `project-docs`: English-language documentation — README content, docstrings, comments.

### Modified Capabilities

None — there are no existing specs.

## Impact

- **Code**: `src/main.py` split into `src/secret_generator/` package; behavior changes listed above.
- **Packaging**: `setup.py` deleted, `requirements.txt` replaced by `pyproject.toml` + `uv.lock`.
- **Tests**: `tests/test_generators.py` rewritten in pytest, new test modules added.
- **Docs**: `README.md`, docstrings, CLI strings, `.gitignore` comments translated to English.
- **CI/repo**: new `.github/workflows/ci.yml`; `dev` branch created and becomes PR target for feature work.
- **Dependencies**: `cryptography` stays the single runtime dependency; `pytest`, `ruff` added as dev dependencies.
