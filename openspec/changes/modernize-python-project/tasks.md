# Tasks

Each numbered group lands as one small pull request into `dev` (one or two focused commits per PR). Tests assert exit codes, file modes, and structure — not exact message text — so the English-translation PR does not break them.

## 1. Gitflow & OpenSpec scaffolding (PR: `chore/gitflow-openspec`)

- [x] 1.1 Create `dev` branch from `main`, push to origin. Verify: `git branch -r` lists `origin/dev`.
- [x] 1.2 Commit OpenSpec scaffolding (`openspec/`, `.opencode/`) to `dev` as a single `chore` commit and push. Verify: `git log origin/dev -1` shows the commit; `main` untouched.

## 2. uv packaging (PR: `feat/uv-packaging`)

- [x] 2.1 Create package skeleton `src/secret_generator/` (`__init__.py`, `__main__.py`, `cli.py` carrying the current `main.py` content unchanged for now); delete `src/main.py`, `setup.py`, `requirements.txt`. Verify: after 2.2, `uv run python -c "import secret_generator"` succeeds.
- [x] 2.2 Add `pyproject.toml` (metadata, version 0.1.0, `requires-python >= 3.10`, `cryptography` runtime dep, dev dependency group with `pytest` + `ruff`, `[project.scripts] secret-generator`, `[tool.ruff]` with `target-version = "py310"`) and generate `uv.lock` via `uv sync`. Verify: `uv sync` completes and `uv run secret-generator --jwt-hmac` prints a secret.
- [x] 2.3 Re-point `tests/test_generators.py` imports to `secret_generator.cli`. Verify: `uv run python -m unittest discover tests` passes.
- [x] 2.4 Fix all ruff findings in the repo. Verify: `uv run ruff check .` and `uv run ruff format --check .` both pass.
- [x] 2.5 Update the README usage block to `uv run secret-generator ...` commands (commands only; full translation lands in group 7). Verify: every command in the README usage block runs in a synced clone.

## 3. Module split (PR: `refactor/split-modules`)

- [x] 3.1 Extract `generators.py` — pure generation functions, no IO and no `sys.exit`. Verify: `uv run python -m unittest discover tests` passes.
- [x] 3.2 Extract `output.py` — `format_output` and `save_to_file` with no argparse imports. Verify: unittest run passes.
- [x] 3.3 Reduce `cli.py` to argparse, orchestration, and `main()`; behavior unchanged. Verify: `uv run secret-generator --all` and `uv run python -m secret_generator --all` print the same section structure; unittest run passes.

## 4. pytest migration (PR: `test/pytest`)

- [ ] 4.1 Convert `test_generators.py` to pytest style (plain functions, `assert`, no `unittest.TestCase`). Verify: `uv run pytest` passes.
- [ ] 4.2 Add `test_cli.py` covering current behavior: each selection flag alone, `--all` sections, `--db-pass N` count, output to stdout via `capsys` (monkeypatched argv, `tmp_path` for any files). Verify: `uv run pytest` passes.
- [ ] 4.3 Add `test_output.py` for formatting (warning banner, `=== CATEGORY ===` sections) and file saving into `tmp_path`. Verify: `uv run pytest` passes.
- [ ] 4.4 Add an RSA round-trip test: parse generated private/public PEM back with `cryptography` and assert 2048 bits / exponent 65537. Verify: `uv run pytest -k rsa` passes.

## 5. Crypto & error-handling fixes (PR: `fix/crypto-errors`)

- [ ] 5.1 Switch RSA private key serialization to PKCS#8 (`BEGIN PRIVATE KEY`) and drop `default_backend()`. Verify: pytest — updated header assertion and round-trip test stay green.
- [ ] 5.2 Remove `sys.exit()` from generators (raise on failure); `cli.main()` maps exceptions to exit 1 and `KeyboardInterrupt` to 130. Verify: pytest — a monkeypatched failing generator yields exit code 1.
- [ ] 5.3 Validate `--db-pass N >= 1` (invalid → usage error) and turn no-selection into a usage error via `parser.error()` (exit 2); introduce shared `SPECIAL_CHARACTERS` constant. Verify: pytest — `--db-pass 0` and no-args both exit 2.

## 6. Secure output file handling (PR: `feat/secure-output`)

- [ ] 6.1 Implement file saving with mode 0600 and `O_EXCL` (no silent overwrite) in `output.py`; add `--force` flag in `cli.py`. Verify: pytest — created file has mode 0600, existing file is refused (exit 1, content unchanged), `--force` overwrites.

## 7. English docs & UX (PR: `docs/english`)

- [ ] 7.1 Translate README fully to English (same structure: features, security notes, usage, development, license) and document the PKCS#8 key format and supported Python versions. Verify: no Cyrillic remains in `README.md`; documented commands run.
- [ ] 7.2 Translate CLI messages, docstrings, and code comments to English. Verify: `uv run pytest` passes and no Cyrillic remains in `src/` or `tests/`.
- [ ] 7.3 Translate `.gitignore` comments to English. Verify: no Cyrillic remains in `.gitignore`.

## 8. CI & release to main (PR: `ci/github-actions`)

- [ ] 8.1 Add `.github/workflows/ci.yml`: `lint` job (ruff check + format check) and `test` job (Python 3.10/3.12/3.14 matrix, uv setup, `uv sync`, `uv run pytest`), triggered on push and PR to `main` and `dev`. Verify: workflow runs green on the PR (`gh run list --branch dev`).
- [ ] 8.2 Open a release-style PR `dev` → `main`, verify CI passes on it, merge, and delete merged feature branches. Verify: CI green on `main`; `git branch -r` shows no stale feature branches.

## Workflow follow-up

- After group 8, mark the change implemented and archive it with OpenSpec (`openspec archive modernize-python-project`).
- Optional manual follow-up (owner): configure GitHub branch protection for `main` and `dev`.
