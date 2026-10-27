"""Connected dashboards and the live broadcast to them.

A single stalled client (phone on a bad network, a suspended tab) must never delay the others:
every send has its own timeout, sends run concurrently, and a client that cannot keep up is
dropped. It reconnects and re-reads the current state from the REST API.
"""
import asyncio
import json
import logging

from fastapi import WebSocket

logger = logging.getLogger("api.websocket")

SEND_TIMEOUT_SECONDS = 2.0


class WebSocketManager:
    def __init__(self) -> None:
        self.connections: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections.add(websocket)
        self.loop = asyncio.get_running_loop()
        logger.info("WebSocket connected. clients=%d", len(self.connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.connections:
            self.connections.discard(websocket)
            logger.info("WebSocket disconnected. clients=%d", len(self.connections))

    async def _send(self, websocket: WebSocket, payload: str) -> bool:
        try:
            await asyncio.wait_for(websocket.send_text(payload), SEND_TIMEOUT_SECONDS)
            return True
        except Exception:                        # includes the timeout of a stalled client
            logger.warning("dropping a WebSocket client that cannot keep up or is gone")
            return False

    async def _drop(self, websocket: WebSocket) -> None:
        self.disconnect(websocket)
        try:                                     # best effort: a stalled socket may not answer
            await asyncio.wait_for(websocket.close(code=1011), 1.0)
        except Exception:
            logger.debug("could not close a dropped WebSocket cleanly")

    async def broadcast(self, message: dict) -> None:
        clients = list(self.connections)
        if not clients:
            return
        payload = json.dumps(message)
        results = await asyncio.gather(*(self._send(ws, payload) for ws in clients))
        failed = [ws for ws, ok in zip(clients, results, strict=True) if not ok]
        if failed:
            await asyncio.gather(*(self._drop(ws) for ws in failed))


manager = WebSocketManager()
