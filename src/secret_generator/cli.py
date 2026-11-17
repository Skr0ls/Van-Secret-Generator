"""
Secret Generator - Безопасная генерация критически важных секретов для production-окружения
"""

import argparse
import sys

from secret_generator.generators import (
    generate_db_password,
    generate_jwt_hmac,
    generate_random_string,
    generate_rsa_key_pair,
)
from secret_generator.output import format_output, save_to_file


def generate_secrets(args) -> dict[str, dict[str, str]]:
    """Генерация секретов на основе аргументов командной строки"""
    secrets_data = {}

    # Генерация JWT секретов
    if args.jwt_hmac or args.all:
        secrets_data.setdefault("JWT", {})["HMAC_SECRET"] = generate_jwt_hmac()

    if args.jwt_rsa or args.all:
        private, public = generate_rsa_key_pair()
        secrets_data.setdefault("JWT", {}).update(
            {"RSA_PRIVATE_KEY": private, "RSA_PUBLIC_KEY": public}
        )

    # Генерация паролей БД
    if args.db_pass or args.all:
        count = args.db_pass if args.db_pass > 0 else 2
        secrets_data["DATABASE"] = {
            f"DB_PASSWORD_{i}": generate_db_password() for i in range(1, count + 1)
        }

    # Генерация секретов приложения
    if args.app_secrets or args.all:
        secrets_data["APP_SECRETS"] = {
            "SECRET_KEY": generate_random_string(64),
            "API_KEY": generate_random_string(32),
        }

    return secrets_data


def parse_arguments():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="Безопасная генерация секретов для production-окружения",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--jwt-hmac", action="store_true", help="Генерация JWT HMAC секрета")
    parser.add_argument("--jwt-rsa", action="store_true", help="Генерация пары RSA ключей для JWT")
    parser.add_argument(
        "--db-pass", type=int, default=0, help="Генерация паролей для БД (укажите количество)"
    )
    parser.add_argument(
        "--app-secrets",
        action="store_true",
        help="Генерация секретов приложения (SECRET_KEY и API_KEY)",
    )
    parser.add_argument("--all", action="store_true", help="Генерация всех доступных секретов")
    parser.add_argument("--output", type=str, help="Имя выходного файла (БУДЬТЕ ОСТОРОЖНЫ С ЭТИМ!)")

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
