from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from .event import RawEvent


class EventQueue:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[RawEvent] = asyncio.Queue()
        self._closed = False

    async def put(self, event: RawEvent) -> None:
        if self._closed:
            raise RuntimeError("cannot enqueue events after queue close")
        await self._queue.put(event)

    @property
    def depth(self) -> int:
        return self._queue.qsize()

    def close(self) -> None:
        self._closed = True

    async def consume(self) -> AsyncIterator[RawEvent]:
        while True:
            if self._closed and self._queue.empty():
                break

            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            try:
                yield event
            finally:
                self._queue.task_done()
