"""Logging configuration for VulnScanner."""

import logging
import sys


def setup_logger(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure and return the application logger.

    Args:
        verbose: If True, emit DEBUG-level messages.
        quiet: If True, only emit WARNING and above.

    Returns:
        Configured Logger instance.
    """
    logger = logging.getLogger("vulnscanner")
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
