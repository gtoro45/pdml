"""
measure_latency.py — Pipeline latency profiler for the PDML detection pipeline.

Measures wall-clock latency across three legs of the pipeline:
  Leg 1 (conn.log  → buffer.csv):  watcher processing latency
  Leg 2 (buffer.csv → pdml print):  pdml window detection latency
  E2E   (conn.log  → pdml print):   total end-to-end latency

Matches records across stages using the 'uid' field.

Usage:
    python measure_latency.py [--conn PATH] [--buf PATH] [--pdml PATH] [--out PATH]

Run this script BEFORE starting live_sim.py + watcher + pdml.py.
It watches all three files concurrently and prints a summary when stdin is closed (Ctrl+C).
"""

import argparse
import os
import sys
import time
import threading
import signal
import numpy as np
from collections import defaultdict

# ── defaults (relative to both live_sim.py and pdml.py) ────────────────────────
DEFAULT_CONN   = "../../train_test_data/demo/conn.log"
DEFAULT_BUF    = "../../buf/buffer.csv"
DEFAULT_PDML   = "pdml_latency_events.log"   # pdml.py writes here (see patch below)
DEFAULT_OUT    = "latency_summary.txt"

WINDOW_SIZE    = 400   # must match pdml.py

# ── shared state ────────────────────────────────────────────────────────────────
lock = threading.Lock()

# uid → wall-clock time (float, seconds since epoch) for each stage
conn_times   = {}   # uid: time line appeared in conn.log
buf_times    = {}   # uid: time line appeared in buffer.csv

# window_id → wall-clock time pdml printed the score for that window
# window_id  → list of uids in that window (first WINDOW_SIZE uids seen by buf watcher, in order)
window_fire_times  = {}   # window_id → float
window_uid_lists   = defaultdict(list)  # window_id → [uid, ...]

# sequential window counter (assigned as each uid arrives in buffer order)
buf_uid_order  = []   # ordered list of uids as they appear in buffer.csv

stop_event = threading.Event()

# ── conn.log watcher ────────────────────────────────────────────────────────────
def watch_conn(path):
    """Tail conn.log and record wall-clock arrival time per uid."""
    # Wait for file to exist
    while not os.path.exists(path) and not stop_event.is_set():
        time.sleep(0.05)

    with open(path, "r") as f:
        # Skip Zeek header lines
        while not stop_event.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.01)
                continue
            line = line.rstrip("\n")
            if line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            uid = parts[1].strip()
            t   = time.time()
            with lock:
                if uid not in conn_times:   # first occurrence wins
                    conn_times[uid] = t

# ── buffer.csv watcher ──────────────────────────────────────────────────────────
def watch_buf(path):
    """Tail buffer.csv, record arrival time per uid, assign to windows."""
    while not os.path.exists(path) and not stop_event.is_set():
        time.sleep(0.05)

    with open(path, "r") as f:
        while not stop_event.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.01)
                continue
            line = line.rstrip("\n")
            if not line:
                continue
            # Format: CONN,ts,uid,...
            parts = line.split(",")
            if len(parts) < 3 or parts[0] != "CONN":
                continue
            uid = parts[2].strip()
            t   = time.time()
            with lock:
                if uid not in buf_times:
                    buf_times[uid] = t
                    buf_uid_order.append(uid)
                    # Assign to a window_id based on insertion order
                    window_id = (len(buf_uid_order) - 1) // WINDOW_SIZE
                    window_uid_lists[window_id].append(uid)

# ── pdml event log watcher ──────────────────────────────────────────────────────
def watch_pdml_events(path):
    """
    Watch the pdml latency event file that the patched pdml.py writes to.
    Each line has the format:   WINDOW_FIRE <window_id> <epoch_float>
    """
    while not os.path.exists(path) and not stop_event.is_set():
        time.sleep(0.05)

    if stop_event.is_set():   # Ctrl+C before file ever appeared
        return

    with open(path, "r") as f:
        while not stop_event.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.05)
                continue
            line = line.strip()
            if not line.startswith("WINDOW_FIRE"):
                continue
            parts = line.split()
            if len(parts) != 3:
                continue
            try:
                window_id = int(parts[1])
                t         = float(parts[2])
            except ValueError:
                continue
            with lock:
                window_fire_times[window_id] = t

# ── stats helper ────────────────────────────────────────────────────────────────
def percentile_stats(samples, label, out_lines):
    if not samples:
        out_lines.append(f"  {label}: no data")
        return
    arr = np.array(samples) * 1000   # convert to ms
    out_lines.append(f"  {label} (n={len(arr)}):")
    out_lines.append(f"    mean  = {np.mean(arr):.1f} ms")
    out_lines.append(f"    p50   = {np.percentile(arr, 50):.1f} ms")
    out_lines.append(f"    p95   = {np.percentile(arr, 95):.1f} ms")
    out_lines.append(f"    p99   = {np.percentile(arr, 99):.1f} ms")
    out_lines.append(f"    max   = {np.max(arr):.1f} ms")

# ── summary ─────────────────────────────────────────────────────────────────────
def print_summary(out_path):
    with lock:
        # Leg 1: conn.log → buffer.csv  (per uid)
        leg1 = []
        matched_leg1 = 0
        for uid, bt in buf_times.items():
            ct = conn_times.get(uid)
            if ct is not None:
                matched_leg1 += 1
                if bt >= ct:
                    leg1.append(bt - ct)

        # Leg 2: buffer.csv (first uid of window) → pdml fire  (per window)
        # E2E:   conn.log  (first uid of window) → pdml fire   (per window)
        leg2 = []
        e2e  = []
        for window_id, fire_t in window_fire_times.items():
            uids = window_uid_lists.get(window_id, [])
            if not uids:
                continue
            first_uid = uids[0]
            bt = buf_times.get(first_uid)
            ct = conn_times.get(first_uid)
            if bt is not None and fire_t >= bt:
                leg2.append(fire_t - bt)
            if ct is not None and fire_t >= ct:
                e2e.append(fire_t - ct)

    lines = []
    lines.append("=" * 52)
    lines.append("  PDML PIPELINE LATENCY SUMMARY")
    lines.append("=" * 52)
    lines.append(f"  Windows fired : {len(window_fire_times)}")
    lines.append(f"  UIDs in conn  : {len(conn_times)}")
    lines.append(f"  UIDs in buf   : {len(buf_times)}")
    lines.append(f"  UIDs matched  : {matched_leg1} / {len(buf_times)}")
    lines.append("")
    percentile_stats(leg1, "Leg 1  conn.log  → buffer.csv  (per uid)", lines)
    lines.append("")
    percentile_stats(leg2, "Leg 2  buffer.csv → pdml print  (per window)", lines)
    lines.append("")
    percentile_stats(e2e,  "E2E    conn.log  → pdml print   (per window)", lines)
    lines.append("=" * 52)

    output = "\n".join(lines)
    print("\n" + output)
    with open(out_path, "w") as f:
        f.write(output + "\n")
    print(f"\n[latency] Summary written to: {out_path}")

# ── entry point ─────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="PDML pipeline latency profiler")
    parser.add_argument("--conn", default=DEFAULT_CONN,  help="Path to conn.log")
    parser.add_argument("--buf",  default=DEFAULT_BUF,   help="Path to buffer.csv")
    parser.add_argument("--pdml", default=DEFAULT_PDML,  help="Path to pdml latency event log")
    parser.add_argument("--out",  default=DEFAULT_OUT,   help="Path to write summary")
    args = parser.parse_args()

    print(f"[latency] Watching:")
    print(f"          conn.log   → {args.conn}")
    print(f"          buffer.csv → {args.buf}")
    print(f"          pdml events→ {args.pdml}")
    print(f"[latency] Press Ctrl+C to stop and print summary.\n")

    threads = [
        threading.Thread(target=watch_conn,         args=(args.conn,),  daemon=True),
        threading.Thread(target=watch_buf,           args=(args.buf,),   daemon=True),
        threading.Thread(target=watch_pdml_events,   args=(args.pdml,),  daemon=True),
    ]
    for t in threads:
        t.start()

    def shutdown(sig, frame):
        print("\n[latency] Stopping watchers...")
        stop_event.set()

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    stop_event.wait()
    time.sleep(0.2)   # let final reads drain
    print_summary(args.out)

if __name__ == "__main__":
    main()