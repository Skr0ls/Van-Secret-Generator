"""Output formatting and persistence for generated secrets."""

import os


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


def save_to_file(content: str, filename: str, force: bool = False) -> None:
    """Сохранение секретов в файл с правами доступа 0600

    Без ``force`` существующий файл не перезаписывается (O_EXCL);
    ошибки ОС пробрасываются вызывающему коду.
    """
    flags = os.O_WRONLY | os.O_CREAT
    if force:
        flags |= os.O_TRUNC
    else:
        flags |= os.O_EXCL

    fd = os.open(filename, flags, 0o600)
    if force and hasattr(os, "fchmod"):
        # Ensure owner-only permissions even on an existing target.
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Секреты сохранены в {filename} (убедитесь, что файл защищен!)")
