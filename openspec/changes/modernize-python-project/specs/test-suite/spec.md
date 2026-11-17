# Spec Delta

## Purpose

Define the pytest-based test suite: framework choice, required coverage of generators, CLI, and output handling, and CI-runnable conditions.

## ADDED Requirements

### Requirement: Pytest as the test framework
The test suite SHALL run with `uv run pytest` and exit 0 on a healthy codebase; tests MUST NOT use `unittest.TestCase` or the `unittest` runner.

#### Scenario: Suite passes
- **WHEN** `uv run pytest` runs in a synced environment
- **THEN** all tests pass and the command exits 0

#### Scenario: No unittest legacy
- **WHEN** the tests directory is inspected
- **THEN** no test file imports or inherits from `unittest`

### Requirement: Generator tests
The suite SHALL cover every generator: HMAC secret format and uniqueness, RSA PEM headers and round-trip parsing, database password complexity, length, and uniqueness, and application secret lengths and alphabet.

#### Scenario: Generators verified
- **WHEN** the generator test module runs
- **THEN** each generator (HMAC, RSA, DB password, app secrets) has at least one passing test asserting its specified guarantees

### Requirement: CLI tests
The suite SHALL cover CLI behavior: no-selection usage error (exit 2), selective and `--all` generation, `--db-pass` count and validation, output file writing with mode 0600, overwrite protection and `--force`, and runtime failure exit code 1 — using temporary directories and captured output, never writing outside them.

#### Scenario: CLI paths verified
- **WHEN** the CLI test module runs
- **THEN** usage errors, selection semantics, file handling, and exit codes are each asserted by at least one test

#### Scenario: Tests are hermetic
- **WHEN** the full suite runs on any machine
- **THEN** it requires no network access and writes files only inside temporary directories

### Requirement: Output formatting tests
The suite SHALL cover output formatting: warning banner presence, category section headers, and secret name-value listing.

#### Scenario: Formatting verified
- **WHEN** the output formatting tests run
- **THEN** the banner and section structure of the formatted output are asserted against the specified format
