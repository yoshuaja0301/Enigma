"""Enable ``python -m enigma ...`` as an alias for the ``enigma`` CLI."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
