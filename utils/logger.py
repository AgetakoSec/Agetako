import logging


def setup_logger(log_file):
    """
    Set up the logger to log both to a file and the console.
    :param log_file: Path to the log file.
    :return: Configured logger.
    """
    logger = logging.getLogger("vulnerability_logger")
    logger.setLevel(logging.DEBUG)

    # File handler for detailed logs (overwrite mode)
    file_handler = logging.FileHandler(log_file, mode="w")  # 上書きモードに変更
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(file_formatter)

    # Console handler for essential logs
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_formatter)

    # Remove existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
