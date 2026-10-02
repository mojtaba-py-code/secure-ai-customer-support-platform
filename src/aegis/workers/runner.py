"""Worker loop: indexes pending knowledge documents and runs housekeeping.

Document parsing/embedding runs here, isolated from the API process, so a large or pathological
upload cannot slow down customer requests. Multiple workers are safe: each document is claimed
with an atomic ``PENDING -> INDEXING`` transition, and documents stuck in ``INDEXING`` (crashed
worker) are returned to the queue after 15 minutes.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from pathlib import Path

from aegis.bootstrap import AppContainer, RequestServices
from aegis.core.config import Settings

logger = logging.getLogger(__name__)

MAINTENANCE_INTERVAL_SECONDS = 300.0


def touch_heartbeat(path: str | None) -> None:
    """Record that the loop is alive (``aegis healthcheck --worker`` reads the file's age)."""
    if not path:
        return
    try:
        Path(path).touch()
    except OSError:
        logger.warning("worker heartbeat not writable", extra={"event": "worker.heartbeat_error"})


async def run_iteration(container: AppContainer, *, maintenance: bool) -> dict[str, int]:
    stats: dict[str, int] = {}
    async with container.sessionmaker() as session:
        services = RequestServices(container, session)
        stats["indexed"] = await services.knowledge.index_pending(limit=20)
        if maintenance:
            stats.update(await services.maintenance.run())
    return stats


async def run_worker(
    settings: Settings, *, once: bool = False, interval_seconds: float = 5.0
) -> None:
    container = AppContainer(settings)
    await container.startup()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):  # not available on Windows
            loop.add_signal_handler(sig, stop.set)
    last_maintenance = 0.0
    logger.info("worker started", extra={"event": "worker.start"})
    try:
        while not stop.is_set():
            now = time.monotonic()
            maintenance = now - last_maintenance >= MAINTENANCE_INTERVAL_SECONDS
            try:
                stats = await run_iteration(container, maintenance=maintenance)
            except Exception:  # keep the worker alive; the next iteration retries
                logger.exception("worker iteration failed", extra={"event": "worker.error"})
                stats = {}
            if maintenance:
                last_maintenance = now
            if any(stats.values()):
                logger.info("worker iteration", extra={"event": "worker.iteration", **stats})
            touch_heartbeat(settings.worker_heartbeat_file)
            if once:
                break
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
    finally:
        await container.close()
        logger.info("worker stopped", extra={"event": "worker.stop"})
