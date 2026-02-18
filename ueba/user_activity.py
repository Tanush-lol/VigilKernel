"""User/session monitor using `last` against wtmp data."""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from typing import Callable


class UserActivityMonitor:
    """Polls login/session state and reports deltas."""

    def __init__(self, interval_seconds: int = 30) -> None:
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_fingerprint = ""

    def start(self, callback: Callable[[str, dict], None], logger: logging.Logger) -> None:
        """Start polling loop in a background thread."""

        def _run() -> None:
            while not self._stop.is_set():
                try:
                    out = subprocess.check_output(
                        ["last", "-F", "-n", "15"],
                        text=True,
                        stderr=subprocess.DEVNULL,
                    ).strip()
                    fingerprint = out.splitlines()[0] if out else ""
                    if fingerprint and fingerprint != self._last_fingerprint:
                        self._last_fingerprint = fingerprint
                        callback("user_activity", {"last_entry": fingerprint})
                except Exception as exc:  # pragma: no cover - defensive path
                    logger.warning("user_activity monitor error: %s", exc)
                time.sleep(self.interval_seconds)

        self._thread = threading.Thread(target=_run, name="user-activity", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop polling and join the thread."""
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
