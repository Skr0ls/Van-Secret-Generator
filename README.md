# 🔐 Van-Secret Generator — Production Secret Generator

**Protect your ♂️Dungeon♂️**

# Secure generation of critical secrets for production environments

![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.10%2B-blueviolet)

## 🚀 Features

- JWT key generation (HMAC / RSA-2048, private keys in PKCS#8 PEM format)
- Strong password generation for databases
- Application secrets (SECRET_KEY, API_KEY)
- Cryptographically secure algorithms
- Flexible CLI with selectable options

## 🛡️ Security

- Built on `cryptography` and `secrets`
- Automatic complexity checks for database passwords
- Modern cryptographic methods
- Output files are written with owner-only permissions (0600) and are never silently overwritten

## ⚙️ Usage

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
# Generate all secret types
uv run secret-generator --all

# Generate only the JWT HMAC secret
uv run secret-generator --jwt-hmac

# Generate RSA keys for JWT
uv run secret-generator --jwt-rsa

# Generate 3 database passwords
uv run secret-generator --db-pass 3

# Generate application secrets
uv run secret-generator --app-secrets

# Save results to a file
uv run secret-generator --all --output secrets.txt

# Overwrite an existing output file
uv run secret-generator --all --output secrets.txt --force
```

## 🔒 Security best practices

- 🔑 Never commit generated secrets
- 🛡️ Use a secret store (Vault, AWS Secrets Manager)
- 🔄 Rotate keys regularly

## 🧪 Development

- Unit tests cover generators, CLI behavior, and output handling
- Install dependencies: `uv sync`
- Run tests: `uv run pytest`
- Lint and format: `uv run ruff check .` and `uv run ruff format .`

## 📜 License

Distributed under the MIT license. Use with care — the authors are not liable for the consequences of improperly stored secrets.
