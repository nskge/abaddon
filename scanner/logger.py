"""Logging configuration for VulnScanner."""

import logging
import sys


def setup_logger(verbose: bool = False) -> logging.Logger:
    """Configure and return the application logger.

    Args:
        verbose: If True, emit DEBUG-level messages.

    Returns:
        Configured Logger instance.
    """
    logger = logging.getLogger("vulnscanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
