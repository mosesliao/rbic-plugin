"""Atomic, stale-safe writes of the onboarding JSON sources.

catalog.json and roles.json are saved the same way: under one exclusive
lock file (<config_dir>/onboarding/.onboarding.lock), only if the file
still has the sha256 it had when it was read (None: it must not exist
yet), through a temp file + fsync + os.replace.
"""

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Optional

from ..admin import exclusive_lock
from . import ONBOARDING_LOCK


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_sha(path) -> Optional[str]:
    """sha256 of a text file's content, or None when it does not exist."""
    path = Path(path)
    return sha256_text(path.read_text(encoding="utf-8")) if path.exists() \
        else None


def atomic_save(path, text: str, expected_sha: Optional[str], *, what: str,
                error=ValueError) -> str:
    """Write `text` to `path` atomically; return its sha256. Raises
    `error` (nothing written) when the file changed since it was read."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with exclusive_lock(path.parent / ONBOARDING_LOCK, what=f"{what} change"):
        if file_sha(path) != expected_sha:
            raise error(f"{path.name} changed since it was read; nothing was "
                        "written. Run the command again.")
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp_",
                                   suffix=path.suffix)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
    return sha256_text(text)
