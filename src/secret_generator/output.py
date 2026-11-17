"""Output formatting and persistence for generated secrets."""

import sys


def format_output(secrets_data: dict[str, dict[str, str]]) -> str:
    """Форматирование вывода секретов"""
    output = []
    output.append("⚠️ WARNING: THESE ARE SENSITIVE CREDENTIALS ⚠️")
    output.append("⚠️ STORE THEM SECURELY AND DO NOT COMMIT TO VCS ⚠️\n")

    for category, values in secrets_data.items():
        output.append(f"=== {category} ===")
        for key, value in values.items():
            output.append(f"{key}:\n{value}\n")
        output.append("")

    return "\n".join(output)


def save_to_file(content: str, filename: str) -> None:
    """Сохранение секретов в файл"""
    try:
        with open(filename, "w") as f:
            f.write(content)
        print(f"Секреты сохранены в {filename} (убедитесь, что файл защищен!)")
    except OSError as e:
        print(f"Ошибка при сохранении в файл: {e}", file=sys.stderr)
        sys.exit(1)
