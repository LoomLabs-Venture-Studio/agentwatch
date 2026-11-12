"""Thread-safe process snapshots.

``psutil.process_iter(attrs=[...])`` writes each result onto ``proc.info`` of a
Process object that psutil caches module-wide and shares between threads, so a
second thread iterating with other attrs overwrites it mid-read (``KeyError:
'pid'``). Here every caller gets its own dict from ``Process.as_dict``.
"""

from __future__ import annotations

import psutil


def snapshot(attrs: list[str]) -> list[dict]:
    """One dict of *attrs* per live process; vanished processes are skipped.

    Attributes psutil cannot read (AccessDenied) are None, as with ``attrs=``.
    """
    out: list[dict] = []
    for proc in psutil.process_iter():
        try:
            out.append(proc.as_dict(attrs=attrs))
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return out
