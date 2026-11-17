# Design

## Context

Current state (verified in repo): a single 170-line `src/main.py` mixes generators, argparse CLI, formatting, and file IO; tests import it via the `src.main` path hack; `setup.py` is fully commented out; `requirements.txt` holds one line (`cryptography>=39.0.0`); README, docstrings, CLI strings, and `.gitignore` comments are in Russian; only `main` exists as a branch; there is no CI, lint, or lockfile. The local machine has uv 0.11.x and Python 3.12/3.14/3.15 installed.

See proposal.md for motivation and the delta specs for required behavior.

## Goals / Non-Goals

**Goals:**

- uv-first developer workflow: `uv sync`, `uv run`, locked deps.
- A real installable package (`secret_generator`) with entry points and clean module separation.
- Small, behavior-level code fixes (crypto format, error handling, output file safety) — each independently reviewable.
- pytest suite covering generators, CLI, and output; CI enforcing lint + tests.
- English-only docs and UX; gitflow with `dev` and small PRs.

**Non-Goals:**

- No new features: no new secret types, no JSON/structured output, no config file support, no key rotation.
- No publishing to PyPI; entry points work locally via uv for now.
- No branch protection rules configured via GitHub settings (noted as a follow-up the owner may do manually).
- No release/versioning automation.

## Decisions

1. **uv with `pyproject.toml` + committed `uv.lock`; dev deps via PEP 735 `[dependency-groups]` (`pytest`, `ruff`).** Alternatives: pip+requirements (no lock, user explicitly wants uv), poetry (extra tool, same need). `setup.py` and `requirements.txt` are deleted, not kept for compatibility — the project has no published consumers.

2. **`requires-python >= 3.10`.** 3.8/3.9 are EOL; 3.10 is the oldest version still receiving attention and keeps the floor low for a small utility. CI matrix: 3.10, 3.12, 3.14. Assumption recorded: initial package version `0.1.0`.

3. **Package layout — src-layout with three modules:**
   - `src/secret_generator/generators.py` — pure generation functions, no IO, no process exit; raises on failure.
   - `src/secret_generator/output.py` — formatting and file saving.
   - `src/secret_generator/cli.py` — argparse, orchestration, exit-code mapping; `main()` entry.
   - `__init__.py` exposes version, `__main__.py` enables `python -m secret_generator`.
   Alternative: keep one file — rejected: no package/entry point possible, tests need the `src.main` hack, and concerns are already tangled.

4. **RSA private keys switch to PKCS#8** (`serialization.PrivateFormat.PKCS8`). It is the modern default; PyJWT and python-jose load it natively. PKCS#1 is kept only if a consumer demands it (none known). `default_backend()` argument is dropped (deprecated since cryptography 3.1).

5. **Error model — no custom exception hierarchy (KISS).** Generators raise standard exceptions (`ValueError` for invalid arguments, runtime errors from `cryptography` propagate); `cli.main()` maps exceptions to exit codes: usage errors via `parser.error()` (exit 2), runtime failures → exit 1, `KeyboardInterrupt` → exit 130. This removes all `sys.exit()` calls from library code.

6. **No-selection → usage error.** `main()` calls `parser.error("no generation options selected ...")`, which prints usage to stderr and exits 2 — matching argparse conventions for invalid usage.

7. **Secure file write via `os.open` flags, not post-hoc `chmod`.** Without `--force`: `os.open(path, O_WRONLY|O_CREAT|O_EXCL, 0o600)` — creation and mode are atomic, no race window, and `O_EXCL` naturally refuses to clobber. With `--force`: `O_WRONLY|O_CREAT|O_TRUNC` still with mode `0o600`. Mode is best-effort on Windows (no POSIX bits); CI runs on Linux.

8. **Password alphabet as a module-level constant** (`SPECIAL_CHARACTERS = "!@#$%^&*()"`, combined alphabet derived once) — removes the duplicated literal in `generate_random_string`/`generate_db_password`.

9. **`--db-pass` semantics.** argparse keeps `type=int`; `main()` validates `N >= 1` (else usage error, exit 2). `--all` yields the current default of 2 passwords when no explicit count is given.

10. **Tests in pytest, three modules:** `test_generators.py` (format/complexity/uniqueness + RSA round-trip load via `cryptography`), `test_cli.py` (exit codes, selections, file handling — `capsys`, `tmp_path`, monkeypatched `sys.argv`), `test_output.py` (formatting). RSA round-trip is the key upgrade over substring checks: generated keys are actually parsed back.

11. **Ruff configured minimally in `pyproject.toml`:** `target-version = "py310"`, default rule set plus `I` (isort) — enough to be useful without style bikeshedding. Formatter = `ruff format`.

12. **CI (`ci.yml`):** two jobs — `lint` (ruff check + format check) and `test` (matrix 3.10/3.12/3.14, `astral-sh/setup-uv`, `uv sync`, `uv run pytest`), triggered on push and PR to `main`/`dev`. Action versions are pinned at implementation time.

13. **Gitflow.** `dev` branches from `main` and lives on; feature branches (`feature/<short-name>`) PR into `dev`; merges to `main` are deliberate stabilization steps, not per-PR. Merge vs rebase per PR is decided at merge time based on history noise (user preference: case-by-case). OpenSpec scaffolding and this change's artifacts are committed on `dev` in the first PR so review history starts clean.

## Risks / Trade-offs

- [PKCS#8 output may break a hypothetical consumer expecting `BEGIN RSA PRIVATE KEY`] → format is documented in README; conversion back is a documented one-liner (`ssh-keygen`/openssl). No known consumers exist.
- [CLI output language changes from Russian to English] → breaking by intent; called out in proposal and PR description. No parsing consumers known.
- [0600 file mode is POSIX-only] → acceptable: real secret storage targets Unix servers/CI; Windows gets best-effort default perms. Documented.
- [--output stores plaintext secrets on disk] → CLI keeps a warning line in output and README tells users to prefer secret managers; out-of-scope to add encryption.
- [RSA keygen makes tests ~0.5s slower] → negligible for this suite size.
- [gitflow overhead on a tiny repo] → accepted by owner; PRs stay small so cost stays low.
- [`uv.lock` churn across PRs] → regenerated per PR touching dependencies only.

## Migration Plan

Implementation lands as ordered, independently reviewable PRs into `dev` (details and checklists in tasks.md):

1. `chore`: gitflow + OpenSpec scaffolding on `dev`.
2. `feat`: uv packaging — `pyproject.toml`, `uv.lock`, package skeleton (`src/secret_generator/`), remove `setup.py`/`requirements.txt`, re-point test imports.
3. `refactor`: split monolith into `generators.py` / `output.py` / `cli.py`.
4. `test`: migrate suite to pytest and expand coverage of current behavior.
5. `fix`: crypto & error-handling fixes (PKCS#8, drop `default_backend`, exceptions instead of `sys.exit`, `--db-pass` validation, usage-error exit 2) with tests updated for the new behavior.
6. `feat`: secure output handling (0600, `O_EXCL` no-overwrite, `--force`) with tests.
7. `docs`: translate README, CLI strings, docstrings, comments to English.
8. `ci`: GitHub Actions workflow (ruff + pytest matrix), then merge `dev` → `main`.

Rollback: each PR reverts independently; `main` is untouched until the end, so rollback for reviewed work is reverting the offending merge commit on `dev`.

## Open Questions

None — remaining specifics (ruff rule additions, action version pins) are implementation-time details that do not affect specs or task breakdown.
