# Spec Delta

## Purpose

Define the command-line interface: flag semantics, output format, exit codes, and secure handling of output files, with all user-facing text in English.

## ADDED Requirements

### Requirement: Secret selection flags
The CLI SHALL provide flags `--jwt-hmac`, `--jwt-rsa`, `--db-pass N`, `--app-secrets`, and `--all`; each selected flag produces its corresponding secrets, and `--all` produces every secret type.

#### Scenario: Selective generation
- **WHEN** the CLI runs with only `--jwt-hmac`
- **THEN** output contains the JWT HMAC secret and no RSA keys, database passwords, or application secrets

#### Scenario: All generation
- **WHEN** the CLI runs with `--all`
- **THEN** output contains JWT HMAC secret, RSA key pair, database passwords, and application secrets

#### Scenario: Default database password count
- **WHEN** the CLI runs with `--all` (or `--db-pass` combined with another selection) without an explicit count
- **THEN** exactly 2 database passwords are generated

### Requirement: Database password count validation
The `--db-pass N` flag SHALL accept only a positive integer N (N >= 1) and SHALL generate exactly N passwords; zero or negative values MUST be rejected as a usage error.

#### Scenario: Explicit count
- **WHEN** the CLI runs with `--db-pass 3`
- **THEN** exactly 3 database passwords are generated

#### Scenario: Invalid count rejected
- **WHEN** the CLI runs with `--db-pass 0` or `--db-pass -1`
- **THEN** the CLI prints an English usage error describing the valid range and exits with code 2

### Requirement: No-selection usage error
Running the CLI without any selection flag SHALL print an English usage hint to standard error and exit with code 2.

#### Scenario: No flags given
- **WHEN** the CLI runs with no arguments
- **THEN** a usage hint is printed to stderr and the process exits with code 2

### Requirement: Output format
The CLI SHALL print a warning banner about sensitive credentials followed by category sections (`=== CATEGORY ===`) listing each secret name and value; all output text SHALL be in English.

#### Scenario: Sectioned output
- **WHEN** secrets are generated and printed to stdout
- **THEN** output starts with the sensitive-credentials warning, and each category appears as a `=== NAME ===` section with its key-value entries

#### Scenario: English only
- **WHEN** any CLI message, warning, or error is printed
- **THEN** the text is entirely in English

### Requirement: Exit codes
The CLI SHALL exit with code 0 on success, 1 on runtime failures (generation or file-save errors), 2 on usage errors, and 130 when interrupted by the user (Ctrl-C).

#### Scenario: Runtime failure
- **WHEN** saving to the output file fails at runtime (e.g., unwritable path)
- **THEN** an English error is printed to stderr and the process exits with code 1

#### Scenario: User interrupt
- **WHEN** the user interrupts the CLI with Ctrl-C
- **THEN** the process exits with code 130 and prints an interruption message to stderr

### Requirement: Secure output file handling
When `--output FILE` is given, the CLI SHALL write the formatted secrets to that file with file mode 0600 on POSIX systems and MUST NOT overwrite an existing file unless `--force` is provided.

#### Scenario: File written with restricted permissions
- **WHEN** the CLI runs with `--output secrets.txt` and the file does not exist
- **THEN** the file is created containing the formatted output and has owner-read/write permissions only (mode 0600) on POSIX systems

#### Scenario: Existing file protected
- **WHEN** the CLI runs with `--output` pointing to an existing file without `--force`
- **THEN** the CLI prints an English error to stderr and exits with code 1, leaving the existing file unchanged

#### Scenario: Force overwrite
- **WHEN** the CLI runs with `--output` pointing to an existing file together with `--force`
- **THEN** the existing file is replaced with the new content and remains mode 0600 on POSIX systems
