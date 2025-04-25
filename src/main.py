import argparse
import secrets
import string
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_random_string(length=32, characters=None):
    """Генерация случайной строки с заданной длиной и набором символов"""
    if characters is None:
        characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(secrets.choice(characters) for _ in range(length))

def generate_jwt_hmac():
    """Генерация HMAC-секрета для JWT"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')

def generate_rsa_key_pair():
    """Генерация пары RSA ключей (2048 бит)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

def generate_db_password(length=16):
    """Генерация сложного пароля для СУБД"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*()" for c in password)):
            return password

def main():
    parser = argparse.ArgumentParser(
        description='Secure Secret Generator for Production',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('--jwt-hmac', action='store_true', help='Generate JWT HMAC secret')
    parser.add_argument('--jwt-rsa', action='store_true', help='Generate RSA key pair for JWT')
    parser.add_argument('--db-pass', type=int, default=0, 
                       help='Generate database passwords (specify number of passwords)')
    parser.add_argument('--app-secrets', action='store_true', 
                       help='Generate application secrets (SECRET_KEY and API_KEY)')
    parser.add_argument('--all', action='store_true', help='Generate all available secrets')
    parser.add_argument('--output', type=str, help='Output file name (BE CAREFUL WITH THIS!)')

    args = parser.parse_args()
    
    if not any(vars(args).values()):
        parser.print_help()
        return

    secrets_data = {}

    # Генерация JWT секретов
    if args.jwt_hmac or args.all:
        secrets_data.setdefault('JWT', {})['HMAC_SECRET'] = generate_jwt_hmac()
    
    if args.jwt_rsa or args.all:
        private, public = generate_rsa_key_pair()
        secrets_data.setdefault('JWT', {}).update({
            'RSA_PRIVATE_KEY': private,
            'RSA_PUBLIC_KEY': public
        })

    # Генерация паролей БД
    if args.db_pass or args.all:
        count = args.db_pass if args.db_pass > 0 else 2
        secrets_data['DATABASE'] = {
            f'DB_PASSWORD_{i}': generate_db_password()
            for i in range(1, count + 1)
        }

    # Генерация секретов приложения
    if args.app_secrets or args.all:
        secrets_data['APP_SECRETS'] = {
            'SECRET_KEY': generate_random_string(64),
            'API_KEY': generate_random_string(32)
        }

    # Формирование вывода
    output = []
    output.append("⚠️ WARNING: THESE ARE SENSITIVE CREDENTIALS ⚠️")
    output.append("⚠️ STORE THEM SECURELY AND DO NOT COMMIT TO VCS ⚠️\n")
    
    for category, values in secrets_data.items():
        output.append(f"=== {category} ===")
        for key, value in values.items():
            output.append(f"{key}:\n{value}\n")
        output.append("")

    result = '\n'.join(output)

    # Вывод результатов
    if args.output:
        with open(args.output, 'w') as f:
            f.write(result)
        print(f"Secrets saved to {args.output} (make sure to secure it!)")
    else:
        print(result)

if __name__ == "__main__":
    main()