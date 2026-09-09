"""Crash-safe reliability snapshots, added by Telegram MCP Enhanced.

Only numeric budgets and deadlines belong here; request context must never be
persisted. Wall time bridges process lifetimes, unlike monotonic timestamps.
"""

from __future__ import annotations

import logging
import os
import tempfile

from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger(__name__)
STATE_FILE = "rate-limit.json"
Number = Annotated[float, Field(ge=0, allow_inf_nan=False, strict=True)]
BucketName = Literal["read", "search", "write", "media", "admin"]


class ReliabilityState(BaseModel):
    """Reject incompatible snapshots as a whole rather than partially restoring."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    saved_at: Number
    buckets: dict[BucketName, Number]
    cooldown_until: Number | None


def load_state(path: Path) -> ReliabilityState | None:
    """Bad local state must not prevent the server from starting."""
    try:
        return ReliabilityState.model_validate_json(path.read_bytes())
    except FileNotFoundError:
        return None
    except (OSError, ValueError, ValidationError):
        # Do not log validation details: a damaged file could contain secrets.
        logger.warning("Cannot read reliability state; starting with fresh limits")
        return None


def save_state(path: Path, state: ReliabilityState) -> None:
    """Replace only a complete snapshot so an interrupted write keeps the old one."""
    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=STATE_FILE + ".",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(state.model_dump_json())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError:
        logger.warning("Cannot write reliability state; restart protection unavailable")
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                logger.warning("Cannot remove temporary reliability state")
