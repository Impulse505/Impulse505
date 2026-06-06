"""Entry point for ``python -m amhf``."""

from __future__ import annotations

from amhf.cli import cli


def main() -> None:
    """Invoke the click CLI group."""
    cli()


if __name__ == "__main__":
    main()
