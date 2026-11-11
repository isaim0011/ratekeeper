"""
ratekeeper — Python bindings via ctypes.

Build the shared library first:
    cargo build --release

Then:
    from ratekeeper import GcraLimiter, TokenBucketLimiter, SlidingWindowLimiter

    limiter = GcraLimiter(limit=100, window_ms=1000, burst=20)
    if limiter.check(key="user-123"):
        print("allowed, remaining:", limiter.remaining)
    else:
        print("denied, retry after:", limiter.retry_after_ms, "ms")
"""

import ctypes
import os
import platform
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ── Library loading ───────────────────────────────────────────────────────────

def _find_lib() -> str:
    system = platform.system()
    name   = {
        "Linux":  "libratekeeper.so",
        "Darwin": "libratekeeper.dylib",
        "Windows": "ratekeeper.dll",
    }.get(system, "libratekeeper.so")

    # Search: env var → repo root → standard lib paths
    if path := os.environ.get("RATEKEEPER_LIB"):
        return path

    candidates = [
        Path(__file__).parents[2] / "target" / "release" / name,
        Path(__file__).parents[2] / "target" / "debug"   / name,
        Path("/usr/local/lib") / name,
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    raise FileNotFoundError(
        f"ratekeeper shared library ({name}) not found. "
        "Run `cargo build --release` and set RATEKEEPER_LIB if needed."
    )


_lib_path = _find_lib()
_lib = ctypes.CDLL(_lib_path)

# ── Struct definitions ────────────────────────────────────────────────────────

class _GcraState(ctypes.Structure):
    _fields_ = [("tat", ctypes.c_uint64)]

class _TokenBucketState(ctypes.Structure):
    _fields_ = [
        ("tokens_scaled",  ctypes.c_uint64),
        ("last_refill_ms", ctypes.c_uint64),
    ]

class _SlidingWindowState(ctypes.Structure):
    _fields_ = [
        ("prev_count",      ctypes.c_uint32),
        ("curr_count",      ctypes.c_uint32),
        ("window_start_ms", ctypes.c_uint64),
        # Matches `CSlidingWindowState` on the Rust side exactly: a
        # real "has this ever been checked" flag, not a `0`-sentinel
        # on `window_start_ms` (which would wrongly collide with a
        # window that legitimately starts at ms 0 — the same bug this
        # crate's internal sliding-window core had and fixed; see its
        # own doc comment in core_nostd.rs for the full story).
        ("initialized",     ctypes.c_uint8),
    ]

class _Decision(ctypes.Structure):
    _fields_ = [
        ("allowed",        ctypes.c_uint8),
        ("remaining",      ctypes.c_uint32),
        ("retry_after_ms", ctypes.c_uint64),
        ("reset_at_ms",    ctypes.c_uint64),
    ]

# ── Function signatures ───────────────────────────────────────────────────────

_lib.ratekeeper_gcra_check.argtypes = [
    ctypes.c_uint32,                    # limit
    ctypes.c_uint64,                    # window_ms
    ctypes.c_uint32,                    # burst
    ctypes.POINTER(_GcraState),
    ctypes.c_uint64,                    # now_ms
    ctypes.POINTER(_Decision),
]
_lib.ratekeeper_gcra_check.restype = None

_lib.ratekeeper_tb_init.argtypes = [
    ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint32,
    ctypes.c_uint64, ctypes.POINTER(_TokenBucketState),
]
_lib.ratekeeper_tb_init.restype = None

_lib.ratekeeper_tb_check.argtypes = [
    ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint32,
    ctypes.POINTER(_TokenBucketState), ctypes.c_uint64, ctypes.POINTER(_Decision),
]
_lib.ratekeeper_tb_check.restype = None

_lib.ratekeeper_sw_check.argtypes = [
    ctypes.c_uint32, ctypes.c_uint64,
    ctypes.POINTER(_SlidingWindowState), ctypes.c_uint64, ctypes.POINTER(_Decision),
]
_lib.ratekeeper_sw_check.restype = None

_lib.ratekeeper_now_ms.argtypes = []
_lib.ratekeeper_now_ms.restype  = ctypes.c_uint64

_lib.ratekeeper_version.argtypes = []
_lib.ratekeeper_version.restype  = ctypes.c_char_p

# ── Public API ────────────────────────────────────────────────────────────────

def version() -> str:
    return _lib.ratekeeper_version().decode()

def now_ms() -> int:
    return _lib.ratekeeper_now_ms()


@dataclass
class Decision:
    allowed:        bool
    remaining:      int
    retry_after_ms: int
    reset_at_ms:    int


class GcraLimiter:
    """
    Per-key GCRA limiter backed by an in-process dict.
    Thread-safe via per-key locks.

    For distributed use, wire `check()` to call the Rust async API over gRPC
    or HTTP instead.
    """

    def __init__(self, limit: int, window_ms: int, burst: int = 0):
        self.limit     = limit
        self.window_ms = window_ms
        self.burst     = burst
        self._states:  dict[str, _GcraState] = {}
        self._locks:   dict[str, threading.Lock] = {}
        self._global   = threading.Lock()

    def _get_or_create(self, key: str):
        with self._global:
            if key not in self._states:
                self._states[key] = _GcraState(tat=0)
                self._locks[key]  = threading.Lock()
        return self._states[key], self._locks[key]

    def check(self, key: str, now: Optional[int] = None) -> Decision:
        t            = now if now is not None else now_ms()
        state, lock  = self._get_or_create(key)
        out          = _Decision()
        with lock:
            _lib.ratekeeper_gcra_check(
                self.limit, self.window_ms, self.burst,
                ctypes.byref(state), t, ctypes.byref(out),
            )
        return Decision(
            allowed        = bool(out.allowed),
            remaining      = out.remaining,
            retry_after_ms = out.retry_after_ms,
            reset_at_ms    = out.reset_at_ms,
        )

    def is_allowed(self, key: str, now: Optional[int] = None) -> bool:
        return self.check(key, now).allowed


class TokenBucketLimiter:
    """Per-key token bucket limiter."""

    def __init__(self, limit: int, window_ms: int, burst: int = 0):
        self.limit     = limit
        self.window_ms = window_ms
        self.burst     = burst
        self._states:  dict[str, _TokenBucketState] = {}
        self._locks:   dict[str, threading.Lock]    = {}
        self._global   = threading.Lock()

    def _get_or_create(self, key: str, now: int):
        with self._global:
            if key not in self._states:
                st = _TokenBucketState()
                _lib.ratekeeper_tb_init(
                    self.limit, self.window_ms, self.burst, now, ctypes.byref(st)
                )
                self._states[key] = st
                self._locks[key]  = threading.Lock()
        return self._states[key], self._locks[key]

    def check(self, key: str, now: Optional[int] = None) -> Decision:
        t            = now if now is not None else now_ms()
        state, lock  = self._get_or_create(key, t)
        out          = _Decision()
        with lock:
            _lib.ratekeeper_tb_check(
                self.limit, self.window_ms, self.burst,
                ctypes.byref(state), t, ctypes.byref(out),
            )
        return Decision(
            allowed        = bool(out.allowed),
            remaining      = out.remaining,
            retry_after_ms = out.retry_after_ms,
            reset_at_ms    = out.reset_at_ms,
        )


class SlidingWindowLimiter:
    """Per-key sliding window limiter. No boundary spike."""

    def __init__(self, limit: int, window_ms: int):
        self.limit     = limit
        self.window_ms = window_ms
        self._states:  dict[str, _SlidingWindowState] = {}
        self._locks:   dict[str, threading.Lock]      = {}
        self._global   = threading.Lock()

    def _get_or_create(self, key: str):
        with self._global:
            if key not in self._states:
                self._states[key] = _SlidingWindowState()
                self._locks[key]  = threading.Lock()
        return self._states[key], self._locks[key]

    def check(self, key: str, now: Optional[int] = None) -> Decision:
        t            = now if now is not None else now_ms()
        state, lock  = self._get_or_create(key)
        out          = _Decision()
        with lock:
            _lib.ratekeeper_sw_check(
                self.limit, self.window_ms,
                ctypes.byref(state), t, ctypes.byref(out),
            )
        return Decision(
            allowed        = bool(out.allowed),
            remaining      = out.remaining,
            retry_after_ms = out.retry_after_ms,
            reset_at_ms    = out.reset_at_ms,
        )


# ── CLI smoke test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"ratekeeper {version()}")

    lim = GcraLimiter(limit=5, window_ms=1000, burst=0)
    t   = 0
    for i in range(7):
        d = lim.check("test-key", now=t)
        # Plain ASCII, not Unicode checkmarks: Windows consoles using a
        # legacy codepage (cp1252 etc.) can't encode "✓"/"✗" and this
        # demo should just work everywhere without the caller needing
        # to configure their terminal's encoding first.
        status = "OK  allow" if d.allowed else f"DENY        (retry in {d.retry_after_ms}ms)"
        print(f"  req {i+1:02d}  t={t:5d}ms  {status}  remaining={d.remaining}")
        t += 200
