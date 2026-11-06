"""Entrypoint for `python -m rag ...`. Delegates to the CLI in __init__.py."""
from . import _cli

if __name__ == "__main__":
    _cli()
