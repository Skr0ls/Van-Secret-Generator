"""Allow running the package as ``python -m secret_generator``."""

import sys

from secret_generator.cli import main

if __name__ == "__main__":
    sys.exit(main())
