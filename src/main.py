#!/usr/bin/env python3
"""
Secret Generator - Безопасная генерация критически важных секретов для production-окружения
"""

import argparse
import base64
import secrets
import string
import sys
from typing import Dict, Tuple, Any, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


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
    try:
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
    except Exception as e:
        print(f"Ошибка при генерации RSA ключей: {e}", file=sys.stderr)
        sys.exit(1)


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


def generate_secrets(args) -> Dict[str, Dict[str, Any]]:
    """Генерация секретов на основе аргументов командной строки"""
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
        
    return secrets_data


def format_output(secrets_data: Dict[str, Dict[str, Any]]) -> str:
    """Форматирование вывода секретов"""
    output = []
    output.append("⚠️ WARNING: THESE ARE SENSITIVE CREDENTIALS ⚠️")
    output.append("⚠️ STORE THEM SECURELY AND DO NOT COMMIT TO VCS ⚠️\n")
    
    for category, values in secrets_data.items():
        output.append(f"=== {category} ===")
        for key, value in values.items():
            output.append(f"{key}:\n{value}\n")
        output.append("")

    return '\n'.join(output)


def save_to_file(content: str, filename: str) -> None:
    """Сохранение секретов в файл"""
    try:
        with open(filename, 'w') as f:
            f.write(content)
        print(f"Секреты сохранены в {filename} (убедитесь, что файл защищен!)")
    except IOError as e:
        print(f"Ошибка при сохранении в файл: {e}", file=sys.stderr)
        sys.exit(1)


def parse_arguments():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description='Безопасная генерация секретов для production-окружения',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('--jwt-hmac', action='store_true', help='Генерация JWT HMAC секрета')
    parser.add_argument('--jwt-rsa', action='store_true', help='Генерация пары RSA ключей для JWT')
    parser.add_argument('--db-pass', type=int, default=0, 
                       help='Генерация паролей для БД (укажите количество)')
    parser.add_argument('--app-secrets', action='store_true', 
                       help='Генерация секретов приложения (SECRET_KEY и API_KEY)')
    parser.add_argument('--all', action='store_true', help='Генерация всех доступных секретов')
    parser.add_argument('--output', type=str, help='Имя выходного файла (БУДЬТЕ ОСТОРОЖНЫ С ЭТИМ!)')

    return parser.parse_args()


def main():
    """Основная функция программы"""
    args = parse_arguments()
    
    if not any([args.jwt_hmac, args.jwt_rsa, args.db_pass, args.app_secrets, args.all]):
        print("Не выбраны опции генерации. Используйте --help для просмотра доступных опций.")
        sys.exit(0)

    secrets_data = generate_secrets(args)
    formatted_output = format_output(secrets_data)
    
    if args.output:
        save_to_file(formatted_output, args.output)
    else:
        print(formatted_output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nОперация отменена пользователем", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Непредвиденная ошибка: {e}", file=sys.stderr)
        sys.exit(1)