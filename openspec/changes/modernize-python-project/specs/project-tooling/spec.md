# Spec Delta

## Purpose

Define how the project is packaged, installed, and developed: uv-managed metadata, entry points, supported Python versions, package layout, and lint/format tooling.

## ADDED Requirements

### Requirement: uv-managed project
The project SHALL be managed with uv: `pyproject.toml` is the single source of packaging metadata, `uv.lock` is committed, and `uv sync` produces a working environment from the lockfile alone.

#### Scenario: Reproducible install
- **WHEN** a fresh clone runs `uv sync`
- **THEN** the environment is created with locked dependency versions and no additional configuration is required

#### Scenario: Legacy packaging files removed
- **WHEN** the repository is inspected after the change
- **THEN** `setup.py` and `requirements.txt` no longer exist

### Requirement: Dependencies declared in pyproject
`pyproject.toml` SHALL declare `cryptography` as the runtime dependency and `pytest` plus `ruff` as dev dependencies (PEP 735 dependency group), so `uv run` exposes them without manual installs.

#### Scenario: Dev tools available
- **WHEN** the project is synced with uv including dev dependencies
- **THEN** `uv run pytest` and `uv run ruff` execute without extra installation steps

### Requirement: Entry points
The project SHALL expose a `secret-generator` console script via `[project.scripts]` and remain runnable as `python -m secret_generator`; both entry points invoke the same CLI behavior.

#### Scenario: Console script
- **WHEN** `uv run secret-generator --all` is executed
- **THEN** the CLI runs and prints generated secrets

#### Scenario: Module invocation
- **WHEN** `uv run python -m secret_generator --all` is executed
- **THEN** the CLI runs with the same behavior as the console script

#### Scenario: Legacy invocation removed
- **WHEN** `python3 src/main.py` is attempted after the change
- **THEN** it fails because `src/main.py` no longer exists

### Requirement: Python version support
The project SHALL declare `requires-python >= 3.10` and the README SHALL document the supported Python versions.

#### Scenario: Supported interpreter
- **WHEN** the project is synced or installed with a Python 3.10+ interpreter
- **THEN** uv accepts the environment without requiring-python conflicts

### Requirement: Source package layout
The code SHALL live in a `src/secret_generator/` package (src-layout), importable as `secret_generator`, with generation logic separated from CLI and output handling; tests import the package by name.

#### Scenario: Package import
- **WHEN** `uv run python -c "import secret_generator"` is executed
- **THEN** the import succeeds

#### Scenario: Separation of concerns
- **WHEN** the package structure is inspected
- **THEN** generation logic, CLI argument handling, and output/file handling live in separate modules with no CLI concerns in the generation module

### Requirement: Ruff lint and format
The project SHALL configure ruff in `pyproject.toml`, and both `uv run ruff check .` and `uv run ruff format --check .` SHALL pass on the entire repository with no errors.

#### Scenario: Clean lint
- **WHEN** ruff check runs on the repository
- **THEN** it reports no errors

#### Scenario: Consistent formatting
- **WHEN** ruff format check runs on the repository
- **THEN** no file requires reformatting
