"""
Logging setup utilities for ISEC.
Provides a simple stdout/stderr tee to a log file.
"""
import logging
import os
import sys
from typing import Optional


class TeeStream:
    def __init__(self, *streams):
        self.streams = [s for s in streams if s is not None]

    def write(self, data):
        for stream in self.streams:
            try:
                stream.write(data)
            except Exception:
                continue
        for stream in self.streams:
            try:
                stream.flush()
            except Exception:
                continue

    def flush(self):
        for stream in self.streams:
            try:
                stream.flush()
            except Exception:
                continue


def setup_logging(log_path: Optional[str], level: str = "INFO") -> Optional[str]:
    if not log_path:
        return None

    log_dir = os.path.dirname(log_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    log_file = open(log_path, "a", encoding="utf-8")
    stdout_stream = sys.stdout
    stderr_stream = sys.stderr
    sys.stdout = TeeStream(stdout_stream, log_file)
    sys.stderr = TeeStream(stderr_stream, log_file)

    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logging.captureWarnings(True)
    logging.getLogger(__name__).info("Logging initialized: %s", log_path)
    return log_path
