"""API web NetMap : scans périodiques, historique SQLite, page de visualisation."""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import scanner

BASE = Path(__file__).parent
DB_PATH = Path(os.getenv("DB_PATH", BASE / "data" / "netmap.db"))
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "300"))      # secondes
PORT_SCAN = os.getenv("PORT_SCAN", "1") == "1"

state = {"scanning": False, "last_scan": None, "network": None,
         "gateway": None, "local_ip": None, "method": None, "error": None}
scan_lock = asyncio.Lock()


# ---------------------------------------------------------------- base de données
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT, hostname TEXT, vendor TEXT, type TEXT,
                ports TEXT DEFAULT '[]',
                label TEXT DEFAULT '',
                is_gateway INTEGER DEFAULT 0, is_self INTEGER DEFAULT 0,
                online INTEGER DEFAULT 0,
                first_seen REAL, last_seen REAL
            )""")


def save_scan(result: dict) -> None:
    now = time.time()
    with db() as c:
        c.execute("UPDATE devices SET online = 0")
        for d in result["devices"]:
            c.execute("""
                INSERT INTO devices (mac, ip, hostname, vendor, type, ports,
                                     is_gateway, is_self, online, first_seen, last_seen)
                VALUES (:mac, :ip, :hostname, :vendor, :type, :ports,
                        :is_gateway, :is_self, 1, :now, :now)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip,
                    hostname = COALESCE(NULLIF(excluded.hostname, ''), devices.hostname),
                    vendor = COALESCE(NULLIF(excluded.vendor, ''), devices.vendor),
                    type = excluded.type, ports = excluded.ports,
                    is_gateway = excluded.is_gateway, is_self = excluded.is_self,
                    online = 1, last_seen = excluded.last_seen
            """, {**d, "ports": json.dumps(d["ports"]), "now": now})


async def run_scan() -> None:
    if scan_lock.locked():
        return
    async with scan_lock:
        state.update(scanning=True, error=None)
        try:
            result = await asyncio.to_thread(scanner.scan, None, PORT_SCAN)
            save_scan(result)
            state.update({k: result[k] for k in ("network", "gateway", "local_ip", "method")})
            state["last_scan"] = time.time()
        except Exception as e:  # on garde l'appli vivante
            state["error"] = f"{type(e).__name__}: {e}"
        finally:
            state["scanning"] = False


async def scan_loop() -> None:
    while True:
        await run_scan()
        await asyncio.sleep(SCAN_INTERVAL)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    task = asyncio.create_task(scan_loop())
    yield
    task.cancel()


app = FastAPI(title="NetMap", lifespan=lifespan)


# ---------------------------------------------------------------- API
@app.get("/api/status")
def status():
    return {**state, "interval": SCAN_INTERVAL}


@app.get("/api/devices")
def devices():
    with db() as c:
        rows = c.execute("SELECT * FROM devices ORDER BY online DESC, ip").fetchall()
    return [{**dict(r), "ports": json.loads(r["ports"] or "[]"),
             "is_gateway": bool(r["is_gateway"]), "is_self": bool(r["is_self"]),
             "online": bool(r["online"])} for r in rows]


@app.post("/api/scan", status_code=202)
async def trigger_scan():
    if state["scanning"]:
        return {"started": False, "reason": "scan déjà en cours"}
    asyncio.create_task(run_scan())
    return {"started": True}


class DevicePatch(BaseModel):
    label: str


@app.patch("/api/devices/{mac}")
def rename(mac: str, patch: DevicePatch):
    with db() as c:
        cur = c.execute("UPDATE devices SET label = ? WHERE mac = ?", (patch.label.strip(), mac.lower()))
    if cur.rowcount == 0:
        raise HTTPException(404, "appareil inconnu")
    return {"ok": True}


@app.delete("/api/devices/{mac}")
def forget(mac: str):
    with db() as c:
        c.execute("DELETE FROM devices WHERE mac = ?", (mac.lower(),))
    return {"ok": True}


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")
