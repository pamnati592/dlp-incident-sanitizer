"""Centralised logging setup for the DLP sanitizer.

Public API: :func:`get_logger`. Each module gets its own logger via
``get_logger(__name__)``, producing hierarchical names that make it
clear which module emitted each line.

Logs go to stderr (Python's default), keeping stdout reserved for the
spec ``"Bad input"`` literal.
"""

from __future__ import annotations

import logging

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str) -> logging.Logger:
    """Return a logger configured with the project's defaults.

    Calls ``logging.basicConfig`` on first use; subsequent calls are
    no-ops because basicConfig only adds a handler if the root logger
    has none yet.
    """
    logging.basicConfig(
        level=logging.INFO,
        format=_LOG_FORMAT,
        datefmt=_DATE_FORMAT,
    )
    return logging.getLogger(name)
