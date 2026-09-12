"""
ThreatLens WebSocket Streaming Connection Manager
=================================================
High-throughput, low-latency WebSocket connection manager broadcasting
live threat alerts and forensic telemetry to connected SOC dashboards.
"""

from datetime import datetime, timezone
import json
import logging
from typing import List, Union

from fastapi import WebSocket, WebSocketDisconnect

from backend.app.schemas import ThreatAlertSchema

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages active frontend WebSocket sessions, client heartbeats, and broadcast fan-out.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accepts and registers a new WebSocket client session."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            "WebSocket client connected. Active connections: %d",
            len(self.active_connections),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Unregisters a disconnected WebSocket client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(
                "WebSocket client disconnected. Remaining connections: %d",
                len(self.active_connections),
            )

    async def broadcast(self, alert: Union[dict, ThreatAlertSchema, str]) -> None:
        """
        Broadcasts a threat alert payload across all connected clients with minimal latency.
        """
        if not self.active_connections:
            return

        if isinstance(alert, ThreatAlertSchema):
            message = alert.model_dump_json()
        elif isinstance(alert, dict):
            message = json.dumps(alert, default=str)
        else:
            message = str(alert)

        disconnected: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except (WebSocketDisconnect, Exception) as exc:
                logger.debug("Failed to deliver alert to client: %s", exc)
                disconnected.append(connection)

        # Cleanup stale connections
        for dead_conn in disconnected:
            self.disconnect(dead_conn)

    async def send_heartbeat(self) -> None:
        """Sends a periodic heartbeat ping to keep stateful connections alive."""
        if not self.active_connections:
            return

        ping_payload = json.dumps({
            "type": "heartbeat",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "active_clients": len(self.active_connections),
        })

        disconnected: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(ping_payload)
            except Exception:
                disconnected.append(connection)

        for dead_conn in disconnected:
            self.disconnect(dead_conn)

    @property
    def client_count(self) -> int:
        """Returns the number of currently connected WebSocket clients."""
        return len(self.active_connections)
