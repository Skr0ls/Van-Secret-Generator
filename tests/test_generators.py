import unittest
import re
from src.main import (
    generate_random_string,
    generate_jwt_hmac,
    generate_db_password,
    generate_rsa_key_pair
)

class TestGenerators(unittest.TestCase):
    
    def test_random_string_length(self):
        """Проверка длины генерируемых случайных строк"""
        for length in [8, 16, 32, 64]:
            result = generate_random_string(length)
            self.assertEqual(len(result), length)
    
    def test_jwt_hmac_format(self):
        """Проверка формата JWT HMAC секрета"""
        result = generate_jwt_hmac()
        # Проверка, что это валидная base64 строка
        self.assertTrue(re.match(r'^[A-Za-z0-9_-]+=*$', result))
    
    def test_db_password_complexity(self):
        """Проверка сложности паролей для БД"""
        for _ in range(5):  # Тестирование нескольких паролей
            password = generate_db_password()
            self.assertTrue(any(c.islower() for c in password))
            self.assertTrue(any(c.isupper() for c in password))
            self.assertTrue(any(c.isdigit() for c in password))
            self.assertTrue(any(c in "!@#$%^&*()" for c in password))
    
    def test_rsa_key_pair(self):
        """Проверка корректности генерации пары RSA ключей"""
        private, public = generate_rsa_key_pair()
        # Проверяем, что ключи не пустые и имеют правильный формат
        self.assertTrue(len(private) > 0)
        self.assertTrue(len(public) > 0)
        # Проверяем, что это действительно PEM-ключи
        self.assertTrue('PRIVATE KEY' in private)
        self.assertTrue('PUBLIC KEY' in public)

if __name__ == '__main__':
    unittest.main()