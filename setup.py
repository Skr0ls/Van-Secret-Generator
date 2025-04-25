# from setuptools import setup, find_packages

# setup(
#     name="secret-generator",
#     version="0.1.0",
#     packages=find_packages(),
#     install_requires=[
#         "cryptography>=39.0.0",
#     ],
#     entry_points={
#         'console_scripts': [
#             'secret-generator=src.main:main',
#         ],
#     },
#     author="Dmitry",
#     description="Безопасная генерация критически важных секретов для production-окружения",
#     keywords="security, secrets, jwt, password",
#     python_requires=">=3.8",
#     classifiers=[
#         "Development Status :: 4 - Beta",
#         "Intended Audience :: Developers",
#         "License :: OSI Approved :: MIT License",
#         "Programming Language :: Python :: 3",
#         "Programming Language :: Python :: 3.8",
#         "Programming Language :: Python :: 3.9",
#         "Programming Language :: Python :: 3.10",
#     ],
# )