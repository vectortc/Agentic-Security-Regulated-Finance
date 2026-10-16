"""Append-only audit ledger with per-case sequence numbers and hash chaining.

`Ledger` is the port; `InMemoryLedger` and `SQLiteLedger` are reference adapters.
Production storage (Postgres, immutable/WORM store, external anchoring) is a
deployment decision. The invariants only need:
append-before-act, durable append, and O(E_case) fetch by case id.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Protocol

from .events import Event, EventType

GENESIS = "0" * 16


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class Ledger(Protocol):
    def append(self, case_id: str | None, type: EventType, data: dict[str, Any] | None = None) -> Event: ...
    def fetch_by_case(self, case_id: str) -> list[Event]: ...
    def untagged(self) -> list[Event]: ...
    def count(self) -> int: ...


class InMemoryLedger:
    def __init__(self, clock=None) -> None:
        self._events: list[Event] = []
        self._seq: dict[str, int] = {}
        self._prev: dict[str, str] = {}
        self._lock = threading.Lock()
        self._clock = clock or _now

    def append(self, case_id, type, data=None):
        with self._lock:
            seq = prev = None
            if case_id is not None:
                seq = self._seq[case_id] = self._seq.get(case_id, 0) + 1
                prev = self._prev.get(case_id, GENESIS)
            e = Event(case_id, seq, type, self._clock(), dict(data or {}), prev or GENESIS)
            e = Event(**{**e.__dict__, "hash": e.compute_hash()})
            if case_id is not None:
                self._prev[case_id] = e.hash
            self._events.append(e)
            return e

    def fetch_by_case(self, case_id):
        return [e for e in self._events if e.case_id == case_id]

    def untagged(self):
        return [e for e in self._events if e.case_id is None]

    def count(self):
        return len(self._events)


class SQLiteLedger:
    """Stdlib SQLite adapter. The UNIQUE(case_id, seq) index is what makes the
    case-indexed fetch O(E_case) and duplicate sequence numbers impossible."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY, case_id TEXT, seq INTEGER, type TEXT NOT NULL, ts TEXT NOT NULL,
      data TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL,
      UNIQUE(case_id, seq));
    CREATE INDEX IF NOT EXISTS ix_case ON events(case_id, seq);
    """

    def __init__(self, path: str = ":memory:", clock=None) -> None:
        import json
        self._json = json
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.executescript(self.SCHEMA)
        self._lock = threading.Lock()
        self._clock = clock or _now

    def append(self, case_id, type, data=None):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            seq = prev = None
            if case_id is not None:
                row = self._db.execute("SELECT seq, hash FROM events WHERE case_id=? ORDER BY seq DESC LIMIT 1", (case_id,)).fetchone()
                seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
            e = Event(case_id, seq, type, self._clock(), dict(data or {}), prev or GENESIS)
            e = Event(**{**e.__dict__, "hash": e.compute_hash()})
            self._db.execute("INSERT INTO events(case_id,seq,type,ts,data,prev_hash,hash) VALUES(?,?,?,?,?,?,?)",
                             (e.case_id, e.seq, e.type.value, e.ts, self._json.dumps(e.data, default=str), e.prev_hash, e.hash))
            self._db.execute("COMMIT")
            return e

    def _rows(self, where: str, args: tuple) -> list[Event]:
        cur = self._db.execute(f"SELECT case_id,seq,type,ts,data,prev_hash,hash FROM events WHERE {where} ORDER BY id", args)
        return [Event(r[0], r[1], EventType(r[2]), r[3], self._json.loads(r[4]), r[5], r[6]) for r in cur]

    def fetch_by_case(self, case_id):
        return self._rows("case_id=?", (case_id,))

    def untagged(self):
        return self._rows("case_id IS NULL", ())

    def count(self):
        return self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
