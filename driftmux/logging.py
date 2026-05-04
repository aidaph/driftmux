from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional


class COLOR:
    RED = "[91m"
    GREEN = "[92m"
    YELLOW = "[93m"
    BLUE = "[94m"
    MAGENTA = "[95m"
    CYAN = "[96m"
    RESET = "[0m"
    BOLD = "[1m"


def get_logger(host: str, output_dir: str = "logs", level: int = logging.INFO) -> logging.Logger:
    logger_name = f"auditbbox.{host}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    logger.propagate = False

    if logger.handlers:
        return logger

    log_dir = Path(output_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    safe_host = host.replace(":", "_").replace("/", "_")
    logfile = log_dir / f"{safe_host}.log"

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def close_logger(logger: Optional[logging.Logger]) -> None:
    if logger is None:
        return
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
