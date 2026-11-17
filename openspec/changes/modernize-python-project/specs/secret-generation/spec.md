# Spec Delta

## Purpose

Define the cryptographic guarantees, formats, and error signaling of every secret the generator produces, independent of how the CLI presents them.

## ADDED Requirements

### Requirement: JWT HMAC secret generation
The generator SHALL produce a JWT HMAC secret that is a URL-safe base64 encoding of exactly 32 cryptographically random bytes.

#### Scenario: HMAC secret format
- **WHEN** a JWT HMAC secret is generated
- **THEN** the value matches `^[A-Za-z0-9_-]{43}=*$` (URL-safe base64 of 32 bytes)

#### Scenario: HMAC secret uniqueness
- **WHEN** two HMAC secrets are generated in sequence
- **THEN** the values are not equal

### Requirement: RSA key pair generation
The generator SHALL produce a 2048-bit RSA key pair with public exponent 65537, serialized as PEM: private key in PKCS#8 form (`-----BEGIN PRIVATE KEY-----`), public key in SubjectPublicKeyInfo form (`-----BEGIN PUBLIC KEY-----`).

#### Scenario: PEM headers
- **WHEN** an RSA key pair is generated
- **THEN** the private PEM starts with `-----BEGIN PRIVATE KEY-----` and the public PEM starts with `-----BEGIN PUBLIC KEY-----`

#### Scenario: Round-trip load
- **WHEN** the generated private and public PEM values are parsed with a standard cryptographic library
- **THEN** both parse successfully as an RSA key pair matching 2048 bits and exponent 65537

### Requirement: Database password generation
The generator SHALL generate database passwords of the requested length (default 16) that contain at least one lowercase letter, one uppercase letter, one digit, and one special character from a single shared special-character alphabet, using a cryptographically secure random source.

#### Scenario: Complexity satisfied
- **WHEN** database passwords are generated repeatedly (e.g., 20 times)
- **THEN** every password contains at least one lowercase, one uppercase, one digit, and one special character from the shared alphabet

#### Scenario: Length respected
- **WHEN** a database password of length N (N >= 8) is requested
- **THEN** the generated password has exactly N characters

#### Scenario: Uniqueness
- **WHEN** multiple database passwords are generated in sequence
- **THEN** the values are distinct from each other

### Requirement: Application secrets generation
The generator SHALL generate application secrets from the shared allowed alphabet: `SECRET_KEY` of length 64 and `API_KEY` of length 32.

#### Scenario: App secret lengths and alphabet
- **WHEN** application secrets are generated
- **THEN** `SECRET_KEY` has 64 characters and `API_KEY` has 32 characters, both consisting only of allowed alphabet characters

### Requirement: Cryptographically secure randomness
All secret generation SHALL rely on the operating system's cryptographically secure random source and MUST NOT use seeded or predictable pseudo-random generators.

#### Scenario: Secure source only
- **WHEN** the generation code is reviewed
- **THEN** every random value is drawn from a cryptographically secure source with no manual seeding

### Requirement: Library-level error signaling
Generation functions SHALL report failures by raising exceptions and MUST NOT terminate the process or write to standard streams themselves.

#### Scenario: Generation failure surfaces as exception
- **WHEN** key generation fails at the library level
- **THEN** an exception propagates to the caller instead of the process exiting from inside the generator
