# Spec Delta

## Purpose

Define the documentation surface of the project and require English as the single language for docs, code comments, and user-facing text.

## ADDED Requirements

### Requirement: English README
The README SHALL be written entirely in English, preserving the current structure: project purpose, features, security notes, usage examples, development instructions, and license section.

#### Scenario: No Russian content remains
- **WHEN** the README is reviewed
- **THEN** all prose, headings, and comments are in English with no Russian text

### Requirement: README reflects the new workflow
README usage and development examples SHALL use the uv workflow (`uv run secret-generator ...`, `uv sync`, `uv run pytest`, `uv run ruff ...`) and MUST NOT reference the removed `python3 src/main.py` invocation, `setup.py`, or `pip install -r requirements.txt`.

#### Scenario: Updated usage examples
- **WHEN** a reader follows the README usage examples
- **THEN** every command works in a freshly cloned, uv-synced repository

### Requirement: English docstrings and comments
All docstrings, code comments, and inline messages in source and test files SHALL be written in English.

#### Scenario: Codebase language audit
- **WHEN** source and test files are reviewed
- **THEN** every docstring and comment is in English

### Requirement: English repository metadata
The `.gitignore` comments and repository description-related text kept in the repository SHALL be in English.

#### Scenario: Gitignore comments
- **WHEN** `.gitignore` is reviewed
- **THEN** all comments are in English
